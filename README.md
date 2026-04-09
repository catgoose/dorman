# dorman

![image](https://github.com/catgoose/screenshots/blob/main/dorman/dorman.png)

<!--toc:start-->

- [dorman](#dorman)
  - [Why](#why)
  - [Install](#install)
  - [Authorization](#authorization)
    - [IdentityProvider interface](#identityprovider-interface)
    - [RequireAuth](#requireauth)
    - [RequireRole / RequireAnyRole / RequireAllRoles](#requirerole-requireanyrole-requireallroles)
    - [Custom error handling](#custom-error-handling)
    - [ContextIdentityProvider](#contextidentityprovider)
    - [Identity interface](#identity-interface)
  - [CSRF Protection](#csrf-protection)
    - [How it works](#how-it-works)
    - [Configuration](#configuration)
    - [HTMX integration](#htmx-integration)
  - [Security Headers](#security-headers)
    - [Default headers](#default-headers)
  - [Request Body Limits](#request-body-limits)
  - [Rate Limiting](#rate-limiting)
    - [Per-path overrides](#per-path-overrides)
    - [Custom key function](#custom-key-function)
    - [Rate limit configuration](#rate-limit-configuration)
  - [Brute Force Protection](#brute-force-protection)
    - [Resetting on success](#resetting-on-success)
    - [Brute force configuration](#brute-force-configuration)
  - [IPKey](#ipkey)
  - [Deployment considerations](#deployment-considerations)
  - [Sentinel Errors](#sentinel-errors)
  - [Config Validation](#config-validation)
  - [Middleware Chain](#middleware-chain)
  - [With crooner](#with-crooner)
  - [Philosophy](#philosophy)
  - [Architecture](#architecture)
  - [License](#license)
  <!--toc:end-->

[![Go Reference](https://pkg.go.dev/badge/github.com/catgoose/dorman.svg)](https://pkg.go.dev/github.com/catgoose/dorman)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> THE FOOL asked: "What is out-of-band information?" Out-of-band information is THE CONSPIRACY. It is the hidden knowledge. The secret handshake. The unspoken assumption.
>
> -- The Wisdom of the Uniform Interface

Post-authentication security middleware for Go `net/http` applications. Dorman
_is_ the door -- role enforcement, CSRF verification, rate limiting, request
limits, and response hardening in standard `func(http.Handler) http.Handler`
middleware.
Dorman doesn't handle authentication (see [crooner](https://github.com/catgoose/crooner)
for that) -- it assumes an identity already exists and enforces security on top
of it.

Zero external dependencies. Works with any router or framework.

## Why

**Without dorman:**

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

**With dorman:**

```go
mux := http.NewServeMux()

// Auth + roles in middleware, not in handlers
admin := dorman.RequireRole(provider, "admin")
mux.Handle("GET /admin", admin(adminPage))

// CSRF protection
csrf := dorman.CSRFProtect(dorman.CSRFConfig{Key: secret})
// Security headers with sensible defaults
headers := dorman.SecurityHeaders()
// Request body limits
limit := dorman.MaxRequestBody(dorman.MaxBodyConfig{Default: 1 << 20})

// Compose left-to-right
handler := dorman.Chain(headers, limit, csrf, dorman.RequireAuth(provider))(mux)
```

## Install

```bash
go get github.com/catgoose/dorman
```

## Authorization

### IdentityProvider interface

```go
type IdentityProvider interface {
	GetIdentity(r *http.Request) (Identity, error)
}
```

Implement this interface to provide identity from any source -- OIDC tokens,
JWTs, database sessions, request headers. Dorman doesn't care where identity
comes from, only that it satisfies the interface.

### RequireAuth

Rejects unauthenticated requests with 401. The identity is stored on the
request context for downstream handlers:

```go
handler := dorman.RequireAuth(provider)(mux)

// In a handler:
mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
	id := dorman.GetIdentity(r)
	fmt.Fprintf(w, "Hello, %s", id.Subject())
})
```

### RequireRole / RequireAnyRole / RequireAllRoles

Role-based access control. Returns 401 for unauthenticated requests and 403
when the identity lacks the required role(s):

```go
// Exact role match
adminOnly := dorman.RequireRole(provider, "admin")
handler := adminOnly(mux)

// Any of these roles (OR)
editorOrAdmin := dorman.RequireAnyRole(provider, []string{"admin", "editor"})
handler := editorOrAdmin(mux)

// All of these roles (AND)
superuser := dorman.RequireAllRoles(provider, []string{"admin", "billing"})
handler := superuser(mux)
```

### Custom error handling

By default, auth middleware returns bare status codes with empty bodies.
Use `AuthErrorHandler` to customize the response -- redirect to a login page,
return HTML, or write structured errors:

```go
auth := dorman.RequireAuth(provider, dorman.AuthErrorHandler(
	func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, dorman.ErrUnauthorized) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	},
))
```

The `err` argument is one of the sentinel errors (`ErrUnauthorized` or
`ErrForbidden`) so you can distinguish 401 vs 403 cases. Works with
`RequireAuth`, `RequireRole`, `RequireAnyRole`, and `RequireAllRoles`.

### ContextIdentityProvider

Reads identity from the request context using a typed key. Use this when your
auth middleware already stores identity on the context:

```go
type myAuthKey struct{}

provider := dorman.ContextIdentityProvider{ContextKey: myAuthKey{}}
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
id := dorman.SimpleIdentity{ID: "user-42", RoleList: []string{"admin", "editor"}}
```

## CSRF Protection

> The server does not remember you. The server does not pine for you between requests. The server has already forgotten you. The server has moved on.
>
> -- The Wisdom of the Uniform Interface

But the server does verify that the request was intentional. CSRF protection
ensures that state-changing requests come from your UI, not from a malicious
third party.

Dorman implements double-submit cookie CSRF protection with HMAC-SHA256. No
external dependencies -- stdlib crypto only.

```go
csrf := dorman.CSRFProtect(dorman.CSRFConfig{
	Key: []byte("32-byte-secret-key-here........."),
})
handler := csrf(mux)

// In a handler or template, get the token:
token := dorman.GetToken(r)
```

### How it works

1. Every request gets a cookie containing a random nonce
2. The CSRF token is `HMAC-SHA256(key, nonce)`, stored on the request context
3. Safe methods (GET, HEAD, OPTIONS, TRACE) set the cookie and context but skip validation
4. Unsafe methods validate: the submitted token must match the expected HMAC -- checked from the request header first, then the form field
5. When `ValidateOrigin` is enabled, the `Origin` header is checked against the request host and any `TrustedOrigins` -- bare-host values (without a scheme) are rejected

### Configuration

```go
dorman.CSRFProtect(dorman.CSRFConfig{
    Key:              secret,             // required, at least 32 bytes
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
    ValidateOrigin:   true,               // check Origin header on unsafe methods (default: false)
    TrustedOrigins:   []string{"https://cdn.example.com"}, // extra allowed origins (request host is always trusted)
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
handler := dorman.SecurityHeaders()(mux) // defaults for everything
```

Or customize:

```go
handler := dorman.SecurityHeaders(dorman.SecurityHeadersConfig{
	// HSTS is disabled by default -- opt in when serving over TLS:
	HSTS: &dorman.HSTSConfig{MaxAge: 63072000, IncludeSubDomains: true},
	// or use the helper: HSTS: dorman.DefaultHSTSConfig(),
	ContentSecurityPolicy: "default-src 'self'",
	PermissionsPolicy:     "camera=(), microphone=()",
})(mux)
```

### Default headers

| Header                       | Default Value                                                  |
| ---------------------------- | -------------------------------------------------------------- |
| `X-Frame-Options`            | `SAMEORIGIN`                                                   |
| `X-Content-Type-Options`     | `nosniff`                                                      |
| `X-XSS-Protection`           | `0` (disabled -- OWASP recommendation)                         |
| `Referrer-Policy`            | `strict-origin-when-cross-origin`                              |
| `Permissions-Policy`         | `camera=(), microphone=(), geolocation=(), payment=(), usb=()` |
| `Cross-Origin-Opener-Policy` | `same-origin`                                                  |
| `Strict-Transport-Security`  | omitted (opt-in -- can break dev without TLS)                  |
| `Content-Security-Policy`    | omitted (app-specific)                                         |

Set any field to `""` to omit that header.

Enable HSTS when serving over TLS:

```go
// Enable HSTS with sensible defaults (2 years, includeSubDomains):
cfg := dorman.DefaultSecurityHeadersConfig()
cfg.HSTS = dorman.DefaultHSTSConfig()
handler := dorman.SecurityHeaders(cfg)(mux)
```

## Request Body Limits

> complexity is apex predator.
>
> -- Layman Grug

Wraps `http.MaxBytesReader` with configurable per-path limits and custom
error handling. Prevents oversized payloads from reaching your handlers:

```go
limit := dorman.MaxRequestBody(dorman.MaxBodyConfig{
	Default: 1 << 20, // 1 MB default
	PerPath: map[string]int64{
		"/upload": 10 << 20, // 10 MB for uploads
	},
})
handler := limit(mux)
```

When a request exceeds the limit, the default response is `413 Request Entity
Too Large`. Provide an `ErrorHandler` to customize:

```go
limit := dorman.MaxRequestBody(dorman.MaxBodyConfig{
	Default: 1 << 20,
	ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
	},
})
```

## Rate Limiting

> grug brain no want million request per second.
>
> -- Layman Grug

Fixed-window rate limiting with per-path overrides, custom key functions, and
exemptions. No external dependencies -- pure stdlib.

```go
limiter, stop := dorman.RateLimit(dorman.RateLimitConfig{
	Requests: 100,
	Window:   time.Minute,
})
defer stop() // stop background cleanup goroutine on shutdown
handler := limiter(mux)
```

### Per-path overrides

Stricter limits for sensitive endpoints:

```go
limiter, stop := dorman.RateLimit(dorman.RateLimitConfig{
	Requests: 100,
	Window:   time.Minute,
	PerPath: map[string]dorman.RateRule{
		"/login":         {Requests: 5, Window: time.Minute},
		"/api/expensive": {Requests: 10, Window: time.Minute},
	},
})
defer stop()
```

### Custom key function

Rate limit by something other than IP:

```go
limiter, stop := dorman.RateLimit(dorman.RateLimitConfig{
	Requests: 100,
	Window:   time.Minute,
	KeyFunc: func(r *http.Request) string {
		return r.Header.Get("X-API-Key")
	},
})
defer stop()
```

### Rate limit configuration

```go
mw, stop := dorman.RateLimit(dorman.RateLimitConfig{
    Requests:        100,                   // max requests per window (required)
    Window:          time.Minute,           // window duration (required)
    KeyFunc:         dorman.IPKey,          // key extractor (default: IPKey)
    PerPath:         map[string]dorman.RateRule{"/login": {Requests: 5, Window: time.Minute}},
    ExemptPaths:     []string{"/health"},
    ExemptFunc:      func(r *http.Request) bool { return r.Header.Get("X-API-Key") != "" },
    ErrorHandler:    func(w http.ResponseWriter, r *http.Request) { ... },
    CleanupInterval: 2 * time.Minute,       // eviction frequency (default: Window)
})
defer stop() // stop background cleanup goroutine
```

## Brute Force Protection

> Big Brain Developer come to Grug and say "Grug, I have achieved enlightenment.
> I have built a micro-frontend architecture with seventeen independently
> deployable SPAs." Grug say nothing for long time. Then Grug say "what it do"
>
> -- The Recorded Sayings of Layman Grug

Tracks failed response status codes and blocks a key after too many failures.
Designed for login and authentication endpoints where repeated 401 responses
indicate a brute-force attack.

```go
brute, stop := dorman.BruteForceProtect(dorman.BruteForceConfig{
	MaxAttempts: 5,
	Cooldown:    15 * time.Minute,
})
defer stop() // stop background cleanup goroutine on shutdown
handler := brute(mux)
```

The brute force middleware wraps the `http.ResponseWriter` to intercept status
codes. The wrapper preserves optional interfaces (`http.Flusher`, `http.Hijacker`,
`http.Pusher`) so it composes safely with SSE, WebSocket upgrades, and HTTP/2
push.

### Resetting on success

Call `ResetFailures` on successful authentication so legitimate users don't get
locked out after a few typos:

```go
mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
	if authenticate(r) {
		dorman.ResetFailures(r)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
})
```

### Brute force configuration

```go
mw, stop := dorman.BruteForceProtect(dorman.BruteForceConfig{
    MaxAttempts:     5,                    // failures before blocking (required)
    Cooldown:        15 * time.Minute,     // block duration (required)
    KeyFunc:         dorman.IPKey,         // key extractor (default: IPKey)
    FailureStatus:   []int{401},           // status codes that count as failures (default: [401])
    ErrorHandler:    func(w http.ResponseWriter, r *http.Request) { ... },
    CleanupInterval: 30 * time.Minute,     // eviction frequency (default: Cooldown)
})
defer stop() // stop background cleanup goroutine
```

## IPKey

Both `RateLimit` and `BruteForceProtect` default to `IPKey` for identifying
clients. `IPKey` checks `X-Forwarded-For` first (using the leftmost IP), then
falls back to `r.RemoteAddr`:

```go
// Used automatically when KeyFunc is nil.
// Or pass it explicitly:
limiter, stop := dorman.RateLimit(dorman.RateLimitConfig{
	Requests: 100,
	Window:   time.Minute,
	KeyFunc:  dorman.IPKey,
})
```

When running behind a reverse proxy, ensure `X-Forwarded-For` is set by a
trusted layer -- dorman trusts whatever value is present.

## Deployment considerations

> past is already past -- don't debug it. future not here yet -- don't optimize
> for it. server return html -- this present moment.
>
> -- Layman Grug

Both rate limiting and brute force protection store all state in process memory.
Keep these constraints in mind when deploying:

- **Single-process only** -- counters and block lists live in the Go process.
  They are not visible to other instances behind a load balancer.
- **Lost on restart** -- a rolling deploy or crash resets every counter to zero.
- **Background eviction** -- both stores run a background cleanup goroutine
  (configurable via `CleanupInterval`) that periodically removes stale entries.
  Rate limit windows are evicted once `now - start >= window duration`. Brute
  force entries are evicted once a blocked key's cooldown expires.
  Sub-threshold brute force entries (keys that have not yet hit `MaxAttempts`)
  are also evicted once they have been idle (based on `lastSeen`) longer than
  the cooldown duration.
- **Graceful shutdown** -- both `RateLimit` and `BruteForceProtect` return a
  `stop` function. Call it (e.g. via `defer stop()`) to terminate the
  background cleanup goroutine when the server shuts down.
- **Horizontal scaling** -- if your service runs as multiple replicas, each
  replica enforces its own independent limits. A client can multiply its
  effective quota by the number of instances.

For single-process deployments the built-in `KeyFunc` (IP-based or custom) is
sufficient. When you need shared state across instances or persistence across
restarts, put a dedicated rate-limiting layer in front (e.g. a reverse proxy,
API gateway, or external store) and use dorman as a local safety net.

## Sentinel Errors

> A resource is the thing-in-itself, the Ding an sich, the Platonic form of your
> user table. You never touch it directly.
>
> -- The Wisdom of the Uniform Interface

Dorman exports sentinel errors for programmatic error handling:

**Authorization:**

| Error                | Meaning                                             |
| -------------------- | --------------------------------------------------- |
| `ErrUnauthorized`    | No identity found (401)                             |
| `ErrForbidden`       | Identity lacks required role(s) (403)               |
| `ErrNoIdentity`      | `ContextIdentityProvider` found no value in context |
| `ErrInvalidIdentity` | Context value does not implement `Identity`         |

**CSRF:**

| Error                 | Meaning                            |
| --------------------- | ---------------------------------- |
| `ErrCSRFTokenMissing` | No token in header or form field   |
| `ErrCSRFTokenInvalid` | Token does not match expected HMAC |

Use `dorman.CSRFError(r)` from inside a custom `ErrorHandler` and match with
`errors.Is`:

```go
csrf := dorman.CSRFProtect(dorman.CSRFConfig{
	Key: secret,
	ErrorHandler: func(w http.ResponseWriter, r *http.Request) {
		switch {
		case errors.Is(dorman.CSRFError(r), dorman.ErrCSRFTokenMissing):
			http.Error(w, "CSRF token missing", http.StatusForbidden)
		case errors.Is(dorman.CSRFError(r), dorman.ErrCSRFTokenInvalid):
			http.Error(w, "CSRF token invalid", http.StatusForbidden)
		default:
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
		}
	},
})
```

## Config Validation

> Student ask Grug about complexity. Grug say: "you do not defeat. you say the
> magic word." Student lean forward. "what is the magic word?" Grug say: "no."
>
> -- The Recorded Sayings of Layman Grug

Dorman panics at startup when required config fields are missing or invalid.
This catches misconfigurations during initialization rather than silently
misbehaving at runtime:

| Constructor         | Panics when                                                  |
| ------------------- | ------------------------------------------------------------ |
| `CSRFProtect`       | `Key` is less than 32 bytes                                  |
| `RateLimit`         | `Requests` or `Window` is zero; same for any `PerPath` entry |
| `BruteForceProtect` | `MaxAttempts` or `Cooldown` is zero                          |

This is intentional -- a misconfigured security middleware that silently passes
all requests is worse than a loud crash at boot.

## Middleware Chain

Composing middleware with nested calls works for two or three layers but
becomes hard to read at scale. `Chain` composes left-to-right -- the first
argument is the outermost middleware:

```go
// Instead of this:
handler := headers(limit(csrf(auth(mux))))

// Write this:
handler := dorman.Chain(headers, limit, csrf, auth)(mux)
```

`Chain` returns a `func(http.Handler) http.Handler`, so it composes with
everything else in the standard middleware idiom.

## With crooner

> Enter the application with a single URI and a set of standardized media types.
> Follow the links. Submit the forms. Let the server drive the state. That is all.
>
> -- The Wisdom of the Uniform Interface

[Crooner](https://github.com/catgoose/crooner) handles authentication (OIDC,
OAuth2, session management). Dorman layers on top for authorization and
security. The two libraries share the same interface conventions -- wiring
them together requires no adapters.

```go
// crooner: "who are you?"
authCfg, _ := crooner.NewAuthConfig(ctx, params)

// dorman: "are you allowed?"
admin := dorman.RequireRole(provider, "admin")

// dorman: request and response security
csrf := dorman.CSRFProtect(dorman.CSRFConfig{Key: secret})
headers := dorman.SecurityHeaders()
limit := dorman.MaxRequestBody(dorman.MaxBodyConfig{Default: 1 << 20})

handler := dorman.Chain(headers, limit, csrf, authCfg.Middleware())(mux)
```

## Philosophy

Dorman follows the [dothog design philosophy](https://github.com/catgoose/dothog/blob/main/PHILOSOPHY.md): standard middleware signatures, zero external dependencies, and the server handles security so handlers can focus on business logic.

> The whole point -- the ENTIRE POINT -- of hypermedia is that the server tells the client what to do next IN THE RESPONSE ITSELF.
>
> -- The Wisdom of the Uniform Interface

Dorman tells the client three things: whether you're allowed in (authz), whether your request is legitimate (CSRF), and how the browser should behave (security headers). All in the middleware, before your handler runs.

## Architecture

```
  HTTP Request
       |
       v
  +-----------------+
  | Security Headers|  X-Frame-Options, HSTS, CSP, ...
  +---------+-------+
            |
  +---------v-------+
  | MaxRequestBody  |  reject oversized payloads
  +---------+-------+
            |
  +---------v-------+
  |  CSRF Protect   |  validate token on unsafe methods
  |                 |  set cookie + context token
  +---------+-------+
            |
  +---------v-------+
  |   RateLimit     |  fixed-window rate limiting
  | BruteForceProtect  track failures, block after threshold
  +---------+-------+
            |
  +---------v-------+
  |  RequireAuth    |  401 if no identity
  |  RequireRole    |  403 if wrong role
  |  RequireAllRoles|  403 if missing any role
  +---------+-------+
            |
  +---------v-------+
  |     handler     |  application logic
  +-----------------+
```

## License

MIT
