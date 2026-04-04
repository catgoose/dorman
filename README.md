# porter

<!--toc:start-->

- [porter](#porter)
  - [Why](#why)
  - [Install](#install)
  - [Authorization](#authorization)
    - [IdentityProvider interface](#identityprovider-interface)
    - [RequireAuth](#requireauth)
    - [RequireRole / RequireAnyRole](#requirerole-requireanyrole)
    - [ContextIdentityProvider](#contextidentityprovider)
    - [Identity interface](#identity-interface)
  - [CSRF Protection](#csrf-protection)
    - [How it works](#how-it-works)
    - [Configuration](#configuration)
    - [HTMX integration](#htmx-integration)
  - [Security Headers](#security-headers)
    - [Default headers](#default-headers)
  - [With crooner](#with-crooner)
  - [Philosophy](#philosophy)
  - [Architecture](#architecture)
  - [License](#license)
  <!--toc:end-->

[![Go Reference](https://pkg.go.dev/badge/github.com/catgoose/porter.svg)](https://pkg.go.dev/github.com/catgoose/porter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![porter](https://raw.githubusercontent.com/catgoose/screenshots/main/porter/porter.png)

> THE FOOL asked: "What is out-of-band information?" Out-of-band information is THE CONSPIRACY. It is the hidden knowledge. The secret handshake. The unspoken assumption.
>
> -- The Wisdom of the Uniform Interface

Authorization, CSRF protection, and security header middleware for Go
`net/http` applications. Porter guards the door — identity checks, role
enforcement, request verification, and response hardening in standard
`func(http.Handler) http.Handler` middleware.

Zero external dependencies. Works with any router or framework.

## Why

**Without porter:**

```go
// Role checks scattered across handlers
func adminHandler(w http.ResponseWriter, r *http.Request) {
	id := getIdentityFromContext(r) // hope this exists
	if id == nil {
		http.Error(w, "", 401)
		return
	}
	hasRole := false
	for _, role := range id.Roles {
		if role == "admin" {
			hasRole = true
			break
		}
	}
	if !hasRole {
		http.Error(w, "", 403)
		return
	}
	// actual handler logic, finally
}

// CSRF: pull in gorilla/csrf, configure separately
// Security headers: set them inline, hope you didn't miss one
// Every handler repeats the same boilerplate
```

**With porter:**

```go
mux := http.NewServeMux()

// Auth + roles in middleware, not in handlers
admin := porter.RequireRole(provider, "admin")
mux.Handle("GET /admin", admin(adminPage))

// CSRF protection
csrf := porter.CSRFProtect(porter.CSRFConfig{Key: secret})
// Security headers with sensible defaults
headers := porter.SecurityHeaders()

handler := headers(csrf(porter.RequireAuth(provider)(mux)))
```

## Install

```bash
go get github.com/catgoose/porter
```

## Authorization

### IdentityProvider interface

```go
type IdentityProvider interface {
	GetIdentity(r *http.Request) (Identity, error)
}
```

Implement this interface to provide identity from any source — OIDC tokens,
JWTs, database sessions, request headers. Porter doesn't care where identity
comes from, only that it satisfies the interface.

### RequireAuth

Rejects unauthenticated requests with 401. The identity is stored on the
request context for downstream handlers:

```go
handler := porter.RequireAuth(provider)(mux)

// In a handler:
mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
	id := porter.GetIdentity(r)
	fmt.Fprintf(w, "Hello, %s", id.Subject())
})
```

### RequireRole / RequireAnyRole

Role-based access control. Returns 401 for unauthenticated requests and 403
when the identity lacks the required role(s):

```go
adminOnly := porter.RequireRole(provider, "admin")
handler := adminOnly(mux)

editorOrAdmin := porter.RequireAnyRole(provider, []string{"admin", "editor"})
handler := editorOrAdmin(mux)
```

### ContextIdentityProvider

Reads identity from the request context using a typed key. Use this when your
auth middleware already stores identity on the context:

```go
type myAuthKey struct{}

provider := porter.ContextIdentityProvider{ContextKey: myAuthKey{}}
```

### Identity interface

```go
type Identity interface {
	Subject() string // unique identifier (user ID, email, etc.)
	Roles() []string // assigned roles
}
```

`SimpleIdentity` is a basic implementation:

```go
id := porter.SimpleIdentity{ID: "user-42", RoleList: []string{"admin", "editor"}}
```

## CSRF Protection

> The server does not remember you. The server does not pine for you between requests. The server has already forgotten you. The server has moved on.
>
> -- The Wisdom of the Uniform Interface

But the server does verify that the request was intentional. CSRF protection
ensures that state-changing requests come from your UI, not from a malicious
third party.

Porter implements double-submit cookie CSRF protection with HMAC-SHA256. No
external dependencies — stdlib crypto only.

```go
csrf := porter.CSRFProtect(porter.CSRFConfig{
	Key: []byte("32-byte-secret-key-here........."),
})
handler := csrf(mux)

// In a handler or template, get the token:
token := porter.GetToken(r)
```

### How it works

1. Every request gets a cookie containing a random nonce
2. The CSRF token is `HMAC-SHA256(key, nonce)`, stored on the request context
3. Safe methods (GET, HEAD, OPTIONS) set the cookie and context but skip validation
4. Unsafe methods (POST, PUT, PATCH, DELETE) validate: the submitted token must
   match the expected HMAC — checked from the request header first, then the form field

### Configuration

```go
porter.CSRFProtect(porter.CSRFConfig{
    Key:              secret,             // required, 32 bytes
    FieldName:        "csrf_token",       // form field name (default)
    RequestHeader:    "X-CSRF-Token",     // header name (default)
    CookieName:       "_csrf",            // cookie name (default)
    CookiePath:       "/",                // cookie path (default)
    MaxAge:           43200,              // 12 hours (default)
    InsecureCookie:   false,              // Secure=true by default; set true for non-HTTPS
    SameSite:         http.SameSiteLaxMode, // (default)
    ExemptPaths:      []string{"/health", "/webhook"},
    ExemptFunc:       func(r *http.Request) bool { return r.Header.Get("X-API-Key") != "" },
    ErrorHandler:     func(w http.ResponseWriter, r *http.Request) { ... },
    RotatePerRequest: false,              // stable token per cookie (default)
    PerRequestPaths:  []string{"/login"}, // rotate only for these paths
})
```

### HTMX integration

Render the token in a `<meta>` tag and attach it via an HTMX listener:

```html
<meta name="csrf-token" content="{{ token }}" />
<script>
  document.body.addEventListener("htmx:configRequest", (e) => {
    e.detail.headers["X-CSRF-Token"] = document.querySelector(
      'meta[name="csrf-token"]',
    ).content;
  });
</script>
```

## Security Headers

> grug not understand why other developer make thing so hard.
>
> -- Layman Grug

One middleware, sensible defaults, every security header you need:

```go
handler := porter.SecurityHeaders()(mux) // defaults for everything
```

Or customize:

```go
handler := porter.SecurityHeaders(porter.SecurityHeadersConfig{
	HSTS:                  &porter.HSTSConfig{MaxAge: 63072000, IncludeSubDomains: true},
	ContentSecurityPolicy: "default-src 'self'",
	PermissionsPolicy:     "camera=(), microphone=()",
})(mux)
```

### Default headers

| Header                       | Default Value                                                  |
| ---------------------------- | -------------------------------------------------------------- |
| `X-Frame-Options`            | `SAMEORIGIN`                                                   |
| `X-Content-Type-Options`     | `nosniff`                                                      |
| `X-XSS-Protection`           | `0` (disabled — OWASP recommendation)                          |
| `Referrer-Policy`            | `strict-origin-when-cross-origin`                              |
| `Permissions-Policy`         | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` |
| `Cross-Origin-Opener-Policy` | `same-origin`                                                  |
| `Strict-Transport-Security`  | `max-age=63072000; includeSubDomains` (2 years)                |
| `Content-Security-Policy`    | omitted (app-specific)                                         |

Set any field to `""` to omit that header.

## With crooner

[Crooner](https://github.com/catgoose/crooner) handles authentication (OIDC,
OAuth2, session management). Porter layers on top for authorization and
security. The two libraries share the same interface conventions — wiring
them together requires no adapters.

```go
// crooner: "who are you?"
authCfg, _ := crooner.NewAuthConfig(ctx, params)

// porter: "are you allowed?"
auth := porter.RequireAuth(provider)
admin := porter.RequireRole(provider, "admin")

// porter: request and response security
csrf := porter.CSRFProtect(porter.CSRFConfig{Key: secret})
headers := porter.SecurityHeaders()

handler := headers(csrf(authCfg.Middleware()(mux)))
```

## Philosophy

Porter follows the [dothog design philosophy](https://github.com/catgoose/dothog/blob/main/PHILOSOPHY.md): standard middleware signatures, zero external dependencies, and the server handles security so handlers can focus on business logic.

> The whole point -- the ENTIRE POINT -- of hypermedia is that the server tells the client what to do next IN THE RESPONSE ITSELF.
>
> -- The Wisdom of the Uniform Interface

Porter tells the client three things: whether you're allowed in (authz), whether your request is legitimate (CSRF), and how the browser should behave (security headers). All in the middleware, before your handler runs.

## Architecture

```
  HTTP Request
       │
       ▼
  ┌─────────────┐
  │  Security   │  X-Frame-Options, HSTS, CSP, ...
  │  Headers    │
  └──────┬──────┘
         │
  ┌──────▼──────┐
  │    CSRF     │  validate token on unsafe methods
  │  Protect    │  set cookie + context token
  └──────┬──────┘
         │
  ┌──────▼──────┐
  │  RequireAuth│  401 if no identity
  │  RequireRole│  403 if wrong role
  └──────┬──────┘
         │
  ┌──────▼──────┐
  │   handler   │  application logic
  └─────────────┘
```

## License

MIT
