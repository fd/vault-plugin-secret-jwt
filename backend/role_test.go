package backend

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	multierror "github.com/hashicorp/go-multierror"
)

func TestRoleBuildClaims(t *testing.T) {
	test := func(
		role *Role,
		extra string,
		expected string,
		expectedErr string,
	) {
		t.Helper()

		role.now = time.Date(2018, 12, 28, 10, 14, 00, 00, time.UTC)

		claims, err := role.BuildClaims([]byte(extra), "foo", "bar")

		if toJSON(t, claims) != compactJSON(t, expected) {
			t.Errorf("\nexpected: %s\nactual:   %s", compactJSON(t, expected), toJSON(t, claims))
		}

		expectedErr = strings.TrimSpace(expectedErr)
		if errString(err) != expectedErr {
			t.Errorf("\nexpected: %s\nactual:   %s", expectedErr, errString(err))
		}
	}

	test(
		&Role{
			TTL: 3600,
			Overrides: []byte(`
				{"aud":["https://example.com"]}
			`),
			Defaults: []byte(`
				{"scopes":["https://example.com", "https://example.net"], "cap":["xx"]}
			`),
		},
		`{"scopes":["https://example.com"]}`,
		`{
			"aud":["https://example.com"],
			"cap":["xx"],
			"exp":1545995640,
			"iat":1545992040,
			"iss":"foo",
			"nbf":1545991740,
			"scopes":["https://example.com"],
			"sub":"bar"
		}`,
		``,
	)

	test(
		&Role{TTL: 3600},
		``,
		`{
			"exp":1545995640,
			"iat":1545992040,
			"iss":"foo",
			"nbf":1545991740,
			"sub":"bar"
		}`,
		``,
	)

	test(
		&Role{TTL: 3600},
		`{
			"aud":["https://example.com"],
			"iss":"baz",
			"sub":"bax",
			"iat":5,
			"exp":8,
			"nbf":3
		}`,
		`null`,
		"6 errors occurred:\n"+
			"	* /aud: \"aud\" cannot match schema\n"+
			"	* /exp: \"exp\" cannot match schema\n"+
			"	* /iat: \"iat\" cannot match schema\n"+
			"	* /iss: \"iss\" cannot match schema\n"+
			"	* /nbf: \"nbf\" cannot match schema\n"+
			"	* /sub: \"sub\" cannot match schema\n",
	)

	test(
		&Role{
			TTL: 3600,
			Defaults: []byte(`{
				"aud":["https://example.com"],
				"iss":"baz",
				"sub":"bax",
				"iat":5,
				"exp":8,
				"nbf":3
			}`),
		},
		``,
		`null`,
		"5 errors occurred:\n"+
			"	* /exp: \"exp\" cannot match schema\n"+
			"	* /iat: \"iat\" cannot match schema\n"+
			"	* /iss: \"iss\" cannot match schema\n"+
			"	* /nbf: \"nbf\" cannot match schema\n"+
			"	* /sub: \"sub\" cannot match schema\n",
	)

	test(
		&Role{
			TTL: 3600,
			Overrides: []byte(`{
				"aud":["https://example.com"],
				"iss":"baz",
				"sub":"bax",
				"iat":5,
				"exp":8,
				"nbf":3
			}`),
		},
		``,
		`null`,
		"5 errors occurred:\n"+
			"	* /exp: \"exp\" cannot match schema\n"+
			"	* /iat: \"iat\" cannot match schema\n"+
			"	* /iss: \"iss\" cannot match schema\n"+
			"	* /nbf: \"nbf\" cannot match schema\n"+
			"	* /sub: \"sub\" cannot match schema\n",
	)

	test(
		&Role{
			TTL: 3600,
			Overrides: []byte(`{
				"aud":true,
				"iss":"baz",
				"sub":"bax",
				"iat":5,
				"exp":8,
				"nbf":3
			}`),
		},
		``,
		`null`,
		"6 errors occurred:\n"+
			"	* /aud: true did Not match any specified AnyOf schemas\n"+
			"	* /exp: \"exp\" cannot match schema\n"+
			"	* /iat: \"iat\" cannot match schema\n"+
			"	* /iss: \"iss\" cannot match schema\n"+
			"	* /nbf: \"nbf\" cannot match schema\n"+
			"	* /sub: \"sub\" cannot match schema\n",
	)

	test(
		&Role{
			TTL: 3600,
			Schema: []byte(`{
				"properties": {
					"scopes": { "type": "array", "items": { "type": "string", "enum": [
						"https://example.com/scope-a",
						"https://example.com/scope-b"
					] } }
				}
			}`),
		},
		`{"scopes": ["https://example.com/scope-c"]}`,
		`null`,
		"1 error occurred:\n"+
			"	* /scopes/0: \"https://example.com... should be one of [\"https://example.com/scope-a\", \"https://example.com/scope-b\"]\n",
	)

	test(
		&Role{
			TTL: 3600,
			Schema: []byte(`{
				"properties": {
					"scopes": { "type": "array", "items": { "type": "string", "enum": [
						"https://example.com/scope-a",
						"https://example.com/scope-b"
					] } }
				}
			}`),
		},
		`{"scopes": ["https://example.com/scope-a"]}`,
		`{
			"exp":1545995640,
			"iat":1545992040,
			"iss":"foo",
			"nbf":1545991740,
			"scopes":["https://example.com/scope-a"],
			"sub":"bar"
		}`,
		``,
	)

}

func assert(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func toJSON(t testing.TB, v interface{}) string {
	t.Helper()

	d, err := json.Marshal(v)
	assert(t, err)

	return string(d)
}

func compactJSON(t testing.TB, v string) string {
	t.Helper()

	if v == "" {
		return v
	}

	var buf bytes.Buffer
	err := json.Compact(&buf, []byte(v))
	assert(t, err)

	return buf.String()
}

func errString(err error) string {
	if err != nil {

		if e, _ := err.(*multierror.Error); e != nil {
			sort.Slice(e.Errors, func(i int, j int) bool {
				return e.Errors[i].Error() < e.Errors[j].Error()
			})
		}

		return strings.TrimSpace(err.Error())
	}
	return ""
}
