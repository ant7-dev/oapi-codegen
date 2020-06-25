// Copyright 2019 DeepMap, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package middleware

import (
	"context"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"io/ioutil"
	"net/http"
	"strings"
)

const EchoContextKey = "oapi-codegen/echo-context"
const UserDataKey = "oapi-codegen/user-data"

// This is an Echo middleware function which validates incoming HTTP requests
// to make sure that they conform to the given OAPI 3.0 specification. When
// OAPI validation failes on the request, we return an HTTP/400.

// Create validator middleware from a YAML file path
func OapiValidatorFromYamlFile(path string) (echo.MiddlewareFunc, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %s", path, err)
	}

	swagger, err := openapi3.NewSwaggerLoader().LoadSwaggerFromData(data)
	if err != nil {
		return nil, fmt.Errorf("error parsing %s as Swagger YAML: %s",
			path, err)
	}
	return OapiRequestValidator(swagger), nil
}

// Create a validator from a swagger object.
func OapiRequestValidator(swagger *openapi3.Swagger) echo.MiddlewareFunc {
	return OapiRequestValidatorWithOptions(swagger, nil)
}

// Options to customize request validation. These are passed through to
// openapi3filter.
type Options struct {
	Options      openapi3filter.Options
	ParamDecoder openapi3filter.ContentParameterDecoder
	UserData     interface{}
	Skipper      echomiddleware.Skipper
}

// Create a validator from a swagger object, with validation options
func OapiRequestValidatorWithOptions(swagger *openapi3.Swagger, options *Options) echo.MiddlewareFunc {
	router := openapi3filter.NewRouter().WithSwagger(swagger)
	skipper := getSkipperFromOptions(options)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if skipper(c) {
				return next(c)
			}

			err := ValidateRequestFromContext(c, router, options)
			if err != nil {
				return err
			}
			return next(c)
		}
	}
}

// Create a validator from a swagger object, with validation options
//func(next http.Handler) http.Handler
func OapiRequestValidatorWithOptionsHttpHandler(swagger *openapi3.Swagger, options *Options, errorHandler func(err error)http.Handler) func(next http.Handler) http.Handler {
	if errorHandler == nil{
		errorHandler = DefaultValidationErrorHandler
	}
	router := openapi3filter.NewRouter().WithSwagger(swagger)
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			err := ValidateHTTPRequest(r, router, options)
			if err != nil {
				errorHandler(err).ServeHTTP(w,r)
			}
			next.ServeHTTP(w,r)
		}
		return http.HandlerFunc(fn)
	}

}

func DefaultValidationErrorHandler(err error) http.Handler{
	switch e := err.(type) {
	case *openapi3filter.RequestError:
		// We've got a bad request
		fn := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(e.Error()))
		}
		return http.HandlerFunc(fn)
	case *openapi3filter.SecurityRequirementsError:
		fn := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(e.Error()))
		}
		return http.HandlerFunc(fn)
	default:
		fn := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(e.Error()))
		}
		return http.HandlerFunc(fn)
	}
}

// This function is called from the middleware above and actually does the work
// of validating a request.
func ValidateHTTPRequest(r *http.Request, router *openapi3filter.Router, options *Options) error {

	route, pathParams, err := router.FindRoute(r.Method, r.URL)

	// We failed to find a matching route for the request.
	if err != nil {
		switch e := err.(type) {
		case *openapi3filter.RouteError:
			// We've got a bad request, the path requested doesn't match
			// either server, or path, or something.
			return echo.NewHTTPError(http.StatusBadRequest, e.Reason)
		default:
			// This should never happen today, but if our upstream code changes,
			// we don't want to crash the server, so handle the unexpected error.
			return echo.NewHTTPError(http.StatusInternalServerError,
				fmt.Sprintf("error validating route: %s", err.Error()))
		}
	}

	validationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
	}

	requestContext := r.Context()

	if options != nil {
		validationInput.Options = &options.Options
		validationInput.ParamDecoder = options.ParamDecoder
		requestContext = context.WithValue(requestContext, UserDataKey, options.UserData)
	}

	err = openapi3filter.ValidateRequest(requestContext, validationInput)
	//for default http handler errors have to be handled by the error handler function
	return err
}

// This function is called from the middleware above and actually does the work
// of validating a request.
func ValidateRequestFromContext(ctx echo.Context, router *openapi3filter.Router, options *Options) error {
	req := ctx.Request()
	route, pathParams, err := router.FindRoute(req.Method, req.URL)

	// We failed to find a matching route for the request.
	if err != nil {
		switch e := err.(type) {
		case *openapi3filter.RouteError:
			// We've got a bad request, the path requested doesn't match
			// either server, or path, or something.
			return echo.NewHTTPError(http.StatusBadRequest, e.Reason)
		default:
			// This should never happen today, but if our upstream code changes,
			// we don't want to crash the server, so handle the unexpected error.
			return echo.NewHTTPError(http.StatusInternalServerError,
				fmt.Sprintf("error validating route: %s", err.Error()))
		}
	}

	validationInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
	}

	// Pass the Echo context into the request validator, so that any callbacks
	// which it invokes make it available.
	requestContext := context.WithValue(context.Background(), EchoContextKey, ctx)

	if options != nil {
		validationInput.Options = &options.Options
		validationInput.ParamDecoder = options.ParamDecoder
		requestContext = context.WithValue(requestContext, UserDataKey, options.UserData)
	}

	err = openapi3filter.ValidateRequest(requestContext, validationInput)
	if err != nil {
		switch e := err.(type) {
		case *openapi3filter.RequestError:
			// We've got a bad request
			// Split up the verbose error by lines and return the first one
			// openapi errors seem to be multi-line with a decent message on the first
			errorLines := strings.Split(e.Error(), "\n")
			return &echo.HTTPError{
				Code:     http.StatusBadRequest,
				Message:  errorLines[0],
				Internal: err,
			}
		case *openapi3filter.SecurityRequirementsError:
			for _, err := range e.Errors {
				httpErr, ok := err.(*echo.HTTPError)
				if ok {
					return httpErr
				}
			}
			return &echo.HTTPError{
				Code:     http.StatusForbidden,
				Message:  e.Error(),
				Internal: err,
			}
		default:
			// This should never happen today, but if our upstream code changes,
			// we don't want to crash the server, so handle the unexpected error.
			return &echo.HTTPError{
				Code:     http.StatusInternalServerError,
				Message:  fmt.Sprintf("error validating request: %s", err),
				Internal: err,
			}
		}
	}
	return nil
}

// Helper function to get the echo context from within requests. It returns
// nil if not found or wrong type.
func GetEchoContext(c context.Context) echo.Context {
	iface := c.Value(EchoContextKey)
	if iface == nil {
		return nil
	}
	eCtx, ok := iface.(echo.Context)
	if !ok {
		return nil
	}
	return eCtx
}

func GetUserData(c context.Context) interface{} {
	return c.Value(UserDataKey)
}

// attempt to get the skipper from the options whether it is set or not
func getSkipperFromOptions(options *Options) echomiddleware.Skipper {
	if options == nil {
		return echomiddleware.DefaultSkipper
	}

	if options.Skipper == nil {
		return echomiddleware.DefaultSkipper
	}

	return options.Skipper
}
