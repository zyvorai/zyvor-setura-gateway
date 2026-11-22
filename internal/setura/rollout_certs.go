package setura

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// certReport says how relative certificate paths of the candidate were handled.
type certReport struct {
	Dir       string   // directory the relative paths were resolved against
	Files     []string // the relative references found, as written
	Rewritten bool     // the installed config has absolute paths
	Missing   []string // references that do not exist under Dir
}

// resolveCandidateCerts resolves relative certFile and keyFile paths of the
// candidate's secrets against the candidate file's directory, always, because
// that is where the files the operator prepared sit next to the candidate. The
// gateway resolves relative paths against the directory of the file it serves,
// which can be a different one, so when the two differ the installed config
// gets absolute paths. When the directories are the same nothing changes and
// the candidate is applied byte for byte.
func resolveCandidateCerts(cand []byte, candDir, liveDir string) ([]byte, *certReport, error) {
	doc, err := decodeNumbers(cand)
	if err != nil {
		return cand, nil, nil // not our job to report invalid JSON here
	}
	secrets := asMap(doc["secrets"])
	rep := &certReport{Dir: candDir}
	for _, name := range sortedKeys(secrets) {
		sm := asMap(secrets[name])
		for _, field := range []string{"certFile", "keyFile"} {
			v := asStr(sm[field])
			if v == "" || filepath.IsAbs(v) {
				continue
			}
			rep.Files = append(rep.Files, v)
			abs := filepath.Join(candDir, v)
			if _, err := os.Stat(abs); err != nil {
				msg := fmt.Sprintf("secrets.%s.%s %q does not exist in %s", name, field, v, candDir)
				if _, e2 := os.Stat(filepath.Join(liveDir, v)); e2 == nil {
					msg += fmt.Sprintf(" (it exists next to the live file in %s; copy it next to the candidate)", liveDir)
				}
				rep.Missing = append(rep.Missing, msg)
			}
			sm[field] = abs
		}
	}
	if len(rep.Files) == 0 {
		return cand, nil, nil
	}
	if candDir == liveDir {
		return cand, rep, nil
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	rep.Rewritten = true
	return append(b, '\n'), rep, nil
}

func (c *certReport) describe(liveDir string) string {
	n := len(c.Files)
	s := fmt.Sprintf("%d relative certificate path(s) in the candidate resolved against the candidate's directory %s", n, c.Dir)
	if c.Rewritten {
		s += fmt.Sprintf(" (not the live file's directory %s); the installed config uses absolute paths", liveDir)
	} else {
		s += " (the same directory as the live file)"
	}
	return s
}

// gatewayScope selects the /stats and /metrics series a rollout judges: the
// routes the candidate adds or changes, the backends they reference, and the
// backends the candidate adds or changes. With no such route or backend (for
// example only a Gateway changed) it returns nil, meaning every series.
func gatewayScope(live, cand []byte) func(key string) bool {
	ld, e1 := decodeNumbers(live)
	cd, e2 := decodeNumbers(cand)
	if e1 != nil || e2 != nil {
		return nil
	}
	ns := asStr(cd["namespace"])
	liveB, candB := asMap(ld["backends"]), asMap(cd["backends"])
	changedBackend := map[string]bool{}
	for _, k := range sortedKeys(candB) {
		if old, ok := liveB[k]; ok && eq(old, candB[k]) {
			continue
		}
		if !strings.Contains(k, "/") {
			k = ns + "/" + k
		}
		changedBackend[k] = true
	}
	set := map[string]bool{}
	for k := range changedBackend {
		set["backend:"+k] = true
	}
	liveRes, candRes := asMap(ld["resources"]), asMap(cd["resources"])
	for _, key := range sortedKeys(candRes) {
		resource, name, _ := strings.Cut(key, "/")
		prefix := ""
		switch resource {
		case route:
		case grpcRoute:
			prefix = "GRPCRoute/"
		default:
			continue
		}
		var refs []string
		touchesChanged := false
		for _, rule := range asList(asMap(candRes[key])["rules"]) {
			for _, ref := range asList(asMap(rule)["backendRefs"]) {
				rm := asMap(ref)
				k := str(rm, "namespace", ns) + "/" + asStr(rm["name"]) + ":" + fmt.Sprint(rm["port"])
				refs = append(refs, k)
				touchesChanged = touchesChanged || changedBackend[k]
			}
		}
		old, existed := liveRes[key]
		if existed && eq(old, candRes[key]) && !touchesChanged {
			continue // unchanged and its backends are unchanged
		}
		set["route:"+prefix+ns+"/"+name] = true
		for _, k := range refs {
			set["backend:"+k] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return func(key string) bool { return set[key] }
}
