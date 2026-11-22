package setura

import "testing"

func TestPathShapeDigitRuns(t *testing.T) {
	for in, want := range map[string]string{
		"/static/app.839201.js":     "/static/app.:n.js",
		"/static/app.839201.min.js": "/static/app.:n.min.js",
		"/v2/page1":                 "/v2/page1",
		"/a/b-12345-c-6789":         "/a/b-:n-c-6789",
		"/cart/42":                  "/cart/:n",
		"/x/12345y":                 "/x/:ny",
	} {
		if got := pathShape(in); got != want {
			t.Errorf("pathShape(%q) = %q, want %q", in, got, want)
		}
	}
}
