package backend

import (
	"encoding/json"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/qri-io/jsonschema"
)

type Role struct {
	Overrides []byte
	Defaults  []byte
	Schema    []byte
	TTL       int

	now time.Time
}

var bareUserValidation = jsonschema.Must(`
{
	"title": "Claims",
	"type": "object",
	"propertyNames": {
		"not": {
			"enum": ["iss", "sub", "aud", "exp", "nbf", "iat", "iat"]
		}
	}
}
`)

var bareStaticValidation = jsonschema.Must(`
{
	"title": "Overrides",
	"type": "object",
	"properties": {
		"aud": { "anyOf": [
			{ "$ref": "#/definitions/stringOrURI" },
			{ "type": "array", "items": { "$ref": "#/definitions/stringOrURI" } }
		] }
	},
	"propertyNames": {
		"not": {
			"enum": ["iss", "sub", "exp", "nbf", "iat", "iat"]
		}
	},
	"definitions": {
		"stringOrURI": { "oneOf": [
			{ "type": "string", "pattern": "^[^:]*$" },
			{ "type": "string", "format": "uri" }
		] }
	}
}
`)

func (r *Role) BuildClaims(claimsJSON []byte, issuer, subject string) (jwt.Claims, error) {
	var (
		result        error
		valErrs       []jsonschema.ValError
		claims        interface{}
		overridesJSON = r.Overrides
		overrides     interface{}
		defaultsJSON  = r.Defaults
		defaults      interface{}
	)

	if len(claimsJSON) == 0 {
		claimsJSON = []byte(`{}`)
	}

	if len(overridesJSON) == 0 {
		overridesJSON = []byte(`{}`)
	}

	if len(defaultsJSON) == 0 {
		defaultsJSON = []byte(`{}`)
	}

	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		result = multierror.Append(result, err)
		return nil, result
	}

	if err := json.Unmarshal(overridesJSON, &overrides); err != nil {
		result = multierror.Append(result, err)
		return nil, result
	}

	if err := json.Unmarshal(defaultsJSON, &defaults); err != nil {
		result = multierror.Append(result, err)
		return nil, result
	}

	// validate with basic schema
	{
		bareUserValidation.Validate("/", claims, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, result
		}

		// valid
	}

	// validate with basic schema
	{
		bareStaticValidation.Validate("/", overrides, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, result
		}

		// valid
	}

	// validate with basic schema
	{
		bareStaticValidation.Validate("/", defaults, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, result
		}

		// valid
	}

	if u, ok := claims.(map[string]interface{}); ok && u != nil {

		// Apply default claims
		if d, ok := defaults.(map[string]interface{}); ok && d != nil {
			for k, v := range d {
				if _, f := u[k]; !f {
					u[k] = v
				}
			}
		}

		// Apply static claims
		if s, ok := overrides.(map[string]interface{}); ok && s != nil {
			for k, v := range s {
				u[k] = v
			}
		}

	}

	// validate with role defined schema
	if len(r.Schema) > 0 {
		var rs jsonschema.RootSchema

		err := json.Unmarshal(r.Schema, &rs)
		if err != nil {
			result = multierror.Append(result, err)
			return nil, result
		}

		rs.Validate("/", claims, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, result
		}

		// valid
	}

	now := time.Now().UTC()
	if !r.now.IsZero() {
		now = r.now
	}
	allClaims := jwt.MapClaims(claims.(map[string]interface{}))
	allClaims["iat"] = now.Unix()
	allClaims["exp"] = now.Add(time.Duration(r.TTL) * time.Second).Unix()
	allClaims["nbf"] = now.Add(-5 * time.Minute).Unix()
	allClaims["iss"] = issuer
	allClaims["sub"] = subject

	return allClaims, nil
}

func (c *Role) Validate() error {

	return nil
}
