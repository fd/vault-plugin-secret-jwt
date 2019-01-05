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

var bareUserSchema = jsonschema.Must(`
{
	"title": "Claims",
	"type": "object",
	"properties": {
		"sub": { "$ref": "#/definitions/stringOrURI" }
	},
	"propertyNames": {
		"not": {
			"enum": ["iss", "aud", "exp", "nbf", "iat", "jti"]
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

var defaultsSchema = jsonschema.Must(`
{
	"title": "Overrides",
	"type": "object",
	"properties": {
		"aud": { "anyOf": [
			{ "$ref": "#/definitions/stringOrURI" },
			{ "type": "array", "items": { "$ref": "#/definitions/stringOrURI" } }
		] },

		"sub": { "$ref": "#/definitions/stringOrURI" }
	},
	"propertyNames": {
		"not": {
			"enum": [ "iss", "exp", "nbf", "iat", "jti"]
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

var overridesSchema = jsonschema.Must(`
{
	"title": "Overrides",
	"type": "object",
	"properties": {
		"aud": { "anyOf": [
			{ "$ref": "#/definitions/stringOrURI" },
			{ "type": "array", "items": { "$ref": "#/definitions/stringOrURI" } }
		] },

		"iss": { "$ref": "#/definitions/stringOrURI" },
		"sub": { "$ref": "#/definitions/stringOrURI" }
	},
	"propertyNames": {
		"not": {
			"enum": [ "exp", "nbf", "iat", "jti"]
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

func (r *Role) BuildClaims(claimsJSON []byte, jti string) (jwt.Claims, time.Time, error) {
	var (
		result        error
		valErrs       []jsonschema.ValError
		claims        interface{}
		overridesJSON = r.Overrides
		overrides     interface{}
		defaultsJSON  = r.Defaults
		defaults      interface{}
		expires       time.Time
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
		return nil, expires, result
	}

	if err := json.Unmarshal(overridesJSON, &overrides); err != nil {
		result = multierror.Append(result, err)
		return nil, expires, result
	}

	if err := json.Unmarshal(defaultsJSON, &defaults); err != nil {
		result = multierror.Append(result, err)
		return nil, expires, result
	}

	// validate with basic schema
	{
		bareUserSchema.Validate("/", claims, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, expires, result
		}

		// valid
	}

	// validate with basic schema
	{
		overridesSchema.Validate("/", overrides, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, expires, result
		}

		// valid
	}

	// validate with basic schema
	{
		defaultsSchema.Validate("/", defaults, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, expires, result
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
		valErrs, err := metaSchema.ValidateBytes([]byte(r.Schema))
		if err != nil {
			result = multierror.Append(result, err)
			return nil, expires, result
		}
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, expires, result
		}

		var rs jsonschema.RootSchema

		err = json.Unmarshal(r.Schema, &rs)
		if err != nil {
			result = multierror.Append(result, err)
			return nil, expires, result
		}

		rs.Validate("/", claims, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return nil, expires, result
		}

		// valid
	}

	now := time.Now().UTC()
	if !r.now.IsZero() {
		now = r.now
	}
	expires = now.Add(time.Duration(r.TTL) * time.Second)
	allClaims := jwt.MapClaims(claims.(map[string]interface{}))
	allClaims["iat"] = now.Unix()
	allClaims["exp"] = expires.Unix()
	allClaims["nbf"] = now.Add(-5 * time.Minute).Unix()
	allClaims["jti"] = jti

	return allClaims, expires, nil
}

func (r *Role) Validate() error {

	var (
		result        error
		valErrs       []jsonschema.ValError
		overridesJSON = r.Overrides
		overrides     interface{}
		defaultsJSON  = r.Defaults
		defaults      interface{}
	)

	if len(overridesJSON) == 0 {
		overridesJSON = []byte(`{}`)
	}

	if len(defaultsJSON) == 0 {
		defaultsJSON = []byte(`{}`)
	}

	if err := json.Unmarshal(overridesJSON, &overrides); err != nil {
		result = multierror.Append(result, err)
		return result
	}

	if err := json.Unmarshal(defaultsJSON, &defaults); err != nil {
		result = multierror.Append(result, err)
		return result
	}

	// validate with basic schema
	{
		overridesSchema.Validate("/", overrides, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return result
		}

		// valid
	}

	// validate with basic schema
	{
		defaultsSchema.Validate("/", defaults, &valErrs)
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return result
		}

		// valid
	}

	// validate with role defined schema
	if len(r.Schema) > 0 {
		valErrs, err := metaSchema.ValidateBytes([]byte(r.Schema))
		if err != nil {
			result = multierror.Append(result, err)
			return result
		}
		for _, err := range valErrs {
			result = multierror.Append(result, err)
		}
		if result != nil {
			return result
		}

		// valid
	}

	return nil
}
