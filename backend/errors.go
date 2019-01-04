package backend

import (
	"encoding/json"
	"sort"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/logical"
)

func errorResponse(err error) (*logical.Response, error) {
	errs := multierror.Append(err).WrappedErrors()
	errStrings := make([]string, len(errs))

	for i, e := range errs {
		errStrings[i] = e.Error()
	}
	sort.Strings(errStrings)

	body, err := json.Marshal(map[string]interface{}{
		"errors": errStrings,
	})
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			logical.HTTPContentType: "application/json",
			logical.HTTPStatusCode:  400,
			logical.HTTPRawBody:     string(body),
		},
	}, nil
}

func CodedError(status int, err error) *codedError {
	return &codedError{
		Status: status,
		Err:    err,
	}
}

type codedError struct {
	Status int
	Err    error
}

func (e *codedError) WrappedErrors() []error {
	err := multierror.Append(e.Err)
	return err.WrappedErrors()
}

func (e *codedError) Error() string {
	return e.Err.Error()
}

func (e *codedError) Code() int {
	return e.Status
}
