package gateway

import (
	"net/http"
	"net/url"
	"strings"
)

// Everything the gateway prints about credentials goes through this file: the
// /config dump, access logs, the explainer, the dashboard state and error
// messages. A secret is replaced by redacted, never truncated or hashed.
const redacted = "<redacted>"

// sensitiveQueryNames are query parameters whose values are credentials in
// common use. Names an API key policy reads are added per request.
var sensitiveQueryNames = map[string]bool{
	"access_token": true, "id_token": true, "token": true, "jwt": true, "api_key": true, "apikey": true,
	"key": true, "secret": true, "password": true, "passwd": true, "pwd": true, "sig": true, "signature": true,
	"auth": true, "authorization": true, "x-api-key": true, "client_secret": true,
}

// sensitiveHeaders are request headers whose values are credentials.
var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "x-api-key": true, "x-auth-token": true,
	"x-admin-token": true,
}

// redactURL removes everything of a URL that may carry a credential: the
// password and user name, and the whole query string and fragment. It is for
// messages and dumps, where the URL is there to identify an endpoint.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Not a URL we can take apart: show nothing rather than risk a secret.
		if i := strings.IndexAny(raw, "?#@"); i >= 0 {
			return raw[:i] + redacted
		}
		return raw
	}
	scheme, host, path := u.Scheme, u.Host, u.EscapedPath()
	out := scheme + "://"
	if u.User != nil {
		out += redacted + "@"
	}
	out += host + path
	if u.RawQuery != "" {
		out += "?" + redacted
	}
	return out
}

// redactQuery blanks the values of credential-carrying parameters in a raw
// query string, keeping the other parameters readable for diagnostics.
func redactQuery(raw string, extra ...string) string {
	if raw == "" {
		return raw
	}
	var parts []string
	for _, kv := range strings.Split(raw, "&") {
		name, _, hasVal := strings.Cut(kv, "=")
		dn, err := url.QueryUnescape(name)
		if err != nil {
			dn = name
		}
		bad := sensitiveQueryNames[strings.ToLower(dn)]
		for _, e := range extra {
			bad = bad || (e != "" && dn == e)
		}
		if bad && hasVal {
			kv = name + "=" + redacted
		}
		parts = append(parts, kv)
	}
	return strings.Join(parts, "&")
}

// redactedHeaders is h with the values of credential headers replaced.
func redactedHeaders(h http.Header, extra ...string) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, v := range h {
		lk := strings.ToLower(k)
		bad := sensitiveHeaders[lk]
		for _, e := range extra {
			bad = bad || (e != "" && strings.EqualFold(e, k))
		}
		if bad {
			out[k] = []string{redacted}
			continue
		}
		out[k] = append([]string(nil), v...)
	}
	return out
}
