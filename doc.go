// Package dorman provides authentication, authorization, CSRF protection,
// rate limiting, and security header middleware for Go net/http applications.
//
// All middleware uses the standard func(http.Handler) http.Handler signature,
// so it composes with any router or framework that supports net/http middleware.
package dorman
