package gateway

import (
	"fmt"
	"strings"
)

// authSecrets are the resolved secrets of an auth policy: the OIDC client
// secret and cookie keys, and the credentials the policy injects. They come
// from the environment, a file or a Kubernetes Secret, the same sources as
// the AI provider keys, and are never part of a dump, log line or error.
type authSecrets struct {
	clientSecret *aiSecret
	cookieKeys   []*aiSecret
	inject       []*aiSecret
}

func (s *authSecrets) client() string {
	if s == nil || s.clientSecret == nil {
		return ""
	}
	return s.clientSecret.get()
}

// authSecretRefs lists the Kubernetes Secret keys a policy names, so the
// Kubernetes source can read them (see loadAIKeys).
func authSecretRefs(p *AuthPolicy) []*AISecretKeyRef {
	if p == nil {
		return nil
	}
	var out []*AISecretKeyRef
	add := func(r *AISecretRef) {
		if r != nil && r.Secret != nil {
			out = append(out, r.Secret)
		}
	}
	if p.OIDC != nil {
		add(p.OIDC.ClientSecret)
		for i := range p.OIDC.CookieKeys {
			add(&p.OIDC.CookieKeys[i])
		}
	}
	for _, in := range p.Inject {
		add(in.Secret)
	}
	return out
}

// resolveAuthSecrets reads the secrets of a compiled policy. kind and ns say
// who owns the policy (for ReferenceGrant checks). A secret that cannot be
// read makes the rule invalid: it is never served half configured. Offline
// views (skipCerts) leave the secrets unresolved.
func (t *Table) resolveAuthSecrets(kind, ns string, p *AuthPolicy) error {
	if p == nil || p.c == nil || !p.c.enabled || t.Cfg.skipCerts {
		return nil
	}
	c := p.c
	if c.oidc == nil && len(c.inject) == 0 {
		return nil
	}
	granted := func(sns, name string) bool { return t.Cfg.granted(kind, ns, "", "Secret", sns, name) }
	res := func(what string, ref *AISecretRef) (*aiSecret, error) {
		s, err := resolveAISecret(ref, ns, t.Cfg.AIKeys, granted)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", AuthKey, what, err)
		}
		return s, nil
	}
	sec := &authSecrets{}
	var err error
	if o := c.oidc; o != nil {
		if o.p.ClientSecret != nil {
			if sec.clientSecret, err = res("oidc.clientSecret", o.p.ClientSecret); err != nil {
				return err
			}
		}
		for i := range o.p.CookieKeys {
			k, err := res(fmt.Sprintf("oidc.cookieKeys[%d]", i), &o.p.CookieKeys[i])
			if err != nil {
				return err
			}
			if len(strings.TrimSpace(k.get())) < 32 {
				return fmt.Errorf("%s: oidc.cookieKeys[%d] (%s) is shorter than 32 characters; generate one with: openssl rand -base64 32", AuthKey, i, k.desc)
			}
			sec.cookieKeys = append(sec.cookieKeys, k)
		}
	}
	for i, in := range c.inject {
		s, err := res(fmt.Sprintf("inject[%d].secret", i), in.d.Secret)
		if err != nil {
			return err
		}
		sec.inject = append(sec.inject, s)
	}
	c.secrets.Store(sec)
	return nil
}

// describeSecrets names the sources of a policy's secrets (never the values),
// for "setura why".
func (p *AuthPolicy) describeSecrets() []string {
	var out []string
	d := func(what string, r *AISecretRef) {
		switch {
		case r == nil:
		case r.Env != "":
			out = append(out, what+": env "+r.Env)
		case r.File != "":
			out = append(out, what+": file "+r.File)
		case r.Secret != nil:
			out = append(out, what+": Secret "+r.Secret.Name+"#"+r.Secret.Key)
		}
	}
	if p.OIDC != nil {
		d("oidc client secret", p.OIDC.ClientSecret)
		for i := range p.OIDC.CookieKeys {
			d(fmt.Sprintf("oidc cookie key %d", i+1), &p.OIDC.CookieKeys[i])
		}
	}
	for _, in := range p.Inject {
		d("inject "+in.Header, in.Secret)
	}
	return out
}
