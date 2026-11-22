package gateway

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// API keys and HTTP basic auth.
//
// Storage formats (printed by "setura gateway hash"):
//
//	API key   sha256$SALT$HEX      SHA-256(salt || key), salt random, base64url.
//	Password  pbkdf2-sha256$N$SALT$KEY   PBKDF2-HMAC-SHA256 from crypto/pbkdf2, N iterations.
//
// API keys are random machine-generated secrets with high entropy, so a salted
// SHA-256 is the right cost; a human password gets PBKDF2. bcrypt and scrypt
// are not in the standard library.

// DefaultPBKDF2Iterations is what "setura gateway hash" uses for passwords.
const DefaultPBKDF2Iterations = 600000

const (
	minPBKDF2Iterations = 1000
	maxPBKDF2Iterations = 10000000
)

// APIKeyPolicy authenticates a shared secret in a header or query parameter.
type APIKeyPolicy struct {
	// Header and Query name where the key is read. With neither set the key is
	// read from the X-API-Key header.
	Header string      `json:"header,omitempty"`
	Query  string      `json:"query,omitempty"`
	Keys   []APIKeyDef `json:"keys"`
	// Forward passes the key on to the backend; by default it is removed.
	Forward bool `json:"forward,omitempty"`
}

// APIKeyDef is one accepted key. Store Hash; Key is the clear text form, kept
// for development and flagged by lint rule SET017.
type APIKeyDef struct {
	Name string `json:"name"`
	Hash string `json:"hash,omitempty"`
	Key  string `json:"key,omitempty"`
}

// BasicPolicy authenticates HTTP basic credentials.
type BasicPolicy struct {
	Realm   string      `json:"realm,omitempty"`
	Users   []BasicUser `json:"users"`
	Forward bool        `json:"forward,omitempty"`
}

// BasicUser is one account. Store Hash; Password is clear text (lint SET017).
type BasicUser struct {
	Name     string `json:"name"`
	Hash     string `json:"hash,omitempty"`
	Password string `json:"password,omitempty"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// HashAPIKey returns the stored form of an API key.
func HashAPIKey(key string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return "sha256$" + b64(salt) + "$" + hex.EncodeToString(saltedSHA256(salt, key)), nil
}

func saltedSHA256(salt []byte, key string) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(key))
	return h.Sum(nil)
}

// HashPassword returns the stored form of a password; iter 0 means
// DefaultPBKDF2Iterations.
func HashPassword(pw string, iter int) (string, error) {
	if iter == 0 {
		iter = DefaultPBKDF2Iterations
	}
	if iter < minPBKDF2Iterations || iter > maxPBKDF2Iterations {
		return "", fmt.Errorf("iterations %d: want %d-%d", iter, minPBKDF2Iterations, maxPBKDF2Iterations)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iter, b64(salt), b64(key)), nil
}

// ---- compiled forms ----

type keyEntry struct {
	name   string
	salt   []byte // nil for a clear text key
	digest []byte // SHA-256(salt||key), or SHA-256(key) for clear text
}

type apiKeyVerifier struct {
	header, query string
	forward       bool
	keys          []keyEntry
}

func compileAPIKey(p *APIKeyPolicy) (*apiKeyVerifier, error) {
	v := &apiKeyVerifier{header: p.Header, query: p.Query, forward: p.Forward}
	if v.header == "" && v.query == "" {
		v.header = "X-API-Key"
	}
	if len(p.Keys) == 0 {
		return nil, fmt.Errorf("apiKey: no keys")
	}
	for i, k := range p.Keys {
		if k.Name == "" {
			return nil, fmt.Errorf("apiKey.keys[%d]: name is required", i)
		}
		switch {
		case k.Hash != "" && k.Key != "":
			return nil, fmt.Errorf("apiKey key %q: give hash or key, not both", k.Name)
		case k.Hash != "":
			parts := strings.Split(k.Hash, "$")
			if len(parts) != 3 || parts[0] != "sha256" {
				return nil, fmt.Errorf("apiKey key %q: hash must look like sha256$SALT$HEX (create one with setura gateway hash --kind apikey)", k.Name)
			}
			salt, err1 := base64.RawURLEncoding.DecodeString(parts[1])
			dig, err2 := hex.DecodeString(parts[2])
			if err1 != nil || err2 != nil || len(dig) != sha256.Size {
				return nil, fmt.Errorf("apiKey key %q: malformed hash", k.Name)
			}
			v.keys = append(v.keys, keyEntry{name: k.Name, salt: salt, digest: dig})
		case k.Key != "":
			sum := sha256.Sum256([]byte(k.Key))
			v.keys = append(v.keys, keyEntry{name: k.Name, digest: sum[:]})
		default:
			return nil, fmt.Errorf("apiKey key %q: hash is required", k.Name)
		}
	}
	return v, nil
}

// extract returns the presented key and where it came from.
func (v *apiKeyVerifier) extract(r *http.Request) string {
	if v.header != "" {
		if s := r.Header.Get(v.header); s != "" {
			return s
		}
	}
	if v.query != "" {
		return r.URL.Query().Get(v.query)
	}
	return ""
}

// check compares the key with every stored key without stopping at a match,
// so the time taken does not say which key (or whether any) matched.
func (v *apiKeyVerifier) check(key string) (name string, ok bool) {
	var plain [sha256.Size]byte
	plainDone := false
	match := 0
	for _, e := range v.keys {
		var got []byte
		if e.salt != nil {
			got = saltedSHA256(e.salt, key)
		} else {
			if !plainDone {
				plain, plainDone = sha256.Sum256([]byte(key)), true
			}
			got = plain[:]
		}
		if subtle.ConstantTimeCompare(got, e.digest) == 1 && match == 0 {
			match, name = 1, e.name
		}
	}
	return name, match == 1
}

// strip removes the credential from the request that goes upstream.
func (v *apiKeyVerifier) strip(r *http.Request) {
	if v.forward {
		return
	}
	if v.header != "" {
		r.Header.Del(v.header)
	}
	if v.query != "" && r.URL.RawQuery != "" {
		q := r.URL.Query()
		if q.Has(v.query) {
			q.Del(v.query)
			r.URL.RawQuery = q.Encode()
		}
	}
}

type basicEntry struct {
	name  string
	iter  int
	salt  []byte
	key   []byte
	plain []byte // SHA-256 of a clear text password
}

type basicVerifier struct {
	realm   string
	forward bool
	users   []basicEntry
	dummy   basicEntry // compared against for unknown users, to hide which names exist

	cacheKey []byte
	mu       sync.Mutex
	cache    map[string]time.Time // HMAC(user, password) of recent successes
}

const (
	basicCacheTTL = 5 * time.Minute
	basicCacheMax = 4096
)

func compileBasic(p *BasicPolicy) (*basicVerifier, error) {
	v := &basicVerifier{realm: p.Realm, forward: p.Forward, cache: map[string]time.Time{}, cacheKey: make([]byte, 32)}
	rand.Read(v.cacheKey)
	if v.realm == "" {
		v.realm = "setura"
	}
	if len(p.Users) == 0 {
		return nil, fmt.Errorf("basic: no users")
	}
	maxIter := minPBKDF2Iterations
	for i, u := range p.Users {
		if u.Name == "" || strings.Contains(u.Name, ":") {
			return nil, fmt.Errorf("basic.users[%d]: name is required and must not contain a colon", i)
		}
		switch {
		case u.Hash != "" && u.Password != "":
			return nil, fmt.Errorf("basic user %q: give hash or password, not both", u.Name)
		case u.Hash != "":
			parts := strings.Split(u.Hash, "$")
			if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
				return nil, fmt.Errorf("basic user %q: hash must look like pbkdf2-sha256$N$SALT$KEY (create one with setura gateway hash --kind password)", u.Name)
			}
			iter, err := strconv.Atoi(parts[1])
			salt, e2 := base64.RawURLEncoding.DecodeString(parts[2])
			key, e3 := base64.RawURLEncoding.DecodeString(parts[3])
			if err != nil || e2 != nil || e3 != nil || iter < minPBKDF2Iterations || iter > maxPBKDF2Iterations || len(key) == 0 {
				return nil, fmt.Errorf("basic user %q: malformed hash (iterations %d-%d)", u.Name, minPBKDF2Iterations, maxPBKDF2Iterations)
			}
			v.users = append(v.users, basicEntry{name: u.Name, iter: iter, salt: salt, key: key})
			if iter > maxIter {
				maxIter = iter
			}
		case u.Password != "":
			sum := sha256.Sum256([]byte(u.Password))
			v.users = append(v.users, basicEntry{name: u.Name, plain: sum[:]})
		default:
			return nil, fmt.Errorf("basic user %q: hash is required", u.Name)
		}
	}
	v.dummy = basicEntry{iter: maxIter, salt: make([]byte, 16), key: make([]byte, 32)}
	return v, nil
}

func (e basicEntry) matches(pw string) bool {
	if e.plain != nil {
		sum := sha256.Sum256([]byte(pw))
		return subtle.ConstantTimeCompare(sum[:], e.plain) == 1
	}
	got, err := pbkdf2.Key(sha256.New, pw, e.salt, e.iter, len(e.key))
	return err == nil && subtle.ConstantTimeCompare(got, e.key) == 1
}

// check verifies a user name and password. A recent success is remembered (as
// an HMAC, never the password) so a client sending credentials on every
// request does not pay for PBKDF2 each time.
func (v *basicVerifier) check(user, pw string, now time.Time) bool {
	mac := hmac.New(sha256.New, v.cacheKey)
	mac.Write([]byte(user))
	mac.Write([]byte{0})
	mac.Write([]byte(pw))
	ck := string(mac.Sum(nil))
	v.mu.Lock()
	if exp, ok := v.cache[ck]; ok && now.Before(exp) {
		v.mu.Unlock()
		return true
	}
	v.mu.Unlock()
	ok := false
	found := false
	for _, e := range v.users {
		if subtle.ConstantTimeCompare([]byte(e.name), []byte(user)) == 1 {
			found = true
			if e.matches(pw) {
				ok = true
			}
		}
	}
	if !found {
		v.dummy.matches(pw) // same work as a real user
	}
	if ok {
		v.mu.Lock()
		if len(v.cache) >= basicCacheMax {
			for k, exp := range v.cache {
				if !now.Before(exp) {
					delete(v.cache, k)
				}
			}
			if len(v.cache) >= basicCacheMax {
				v.cache = map[string]time.Time{}
			}
		}
		v.cache[ck] = now.Add(basicCacheTTL)
		v.mu.Unlock()
	}
	return ok
}

func (v *basicVerifier) challenge() string {
	return `Basic realm=` + strconv.Quote(v.realm) + `, charset="UTF-8"`
}
