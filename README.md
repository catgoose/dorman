# porter

[![Go Reference](https://pkg.go.dev/badge/github.com/catgoose/porter.svg)](https://pkg.go.dev/github.com/catgoose/porter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![porter](https://raw.githubusercontent.com/catgoose/screenshots/main/porter/porter.png)

Session settings middleware and identity helpers for Go `net/http`
applications. Works with or without an external auth provider (like
[crooner](https://github.com/catgoose/crooner)).

All middleware uses the standard `func(http.Handler) http.Handler` signature,
so it composes with any router or framework that supports net/http middleware.

## Install

```bash
go get github.com/catgoose/porter
```

## Quick start

```go
package main

import (
    "net/http"
    "github.com/catgoose/porter"
)

func main() {
    mux := http.NewServeMux()

    // Session settings (requires a SessionSettingsProvider implementation)
    session := porter.SessionSettingsMiddleware(repo, nil)

    // Auth middleware
    auth := porter.RequireAuth(provider)

    // Compose middleware
    handler := auth(session(mux))

    http.ListenAndServe(":8080", handler)
}
```

## CSRF protection

Porter does not include CSRF middleware. For CSRF protection, use
[gorilla/csrf](https://github.com/gorilla/csrf) or a similar dedicated library.

## Authorization

Porter provides identity extraction and role-based authorization middleware.

### IdentityProvider interface

```go
type IdentityProvider interface {
    GetIdentity(r *http.Request) (Identity, error)
}
```

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

editorOrAdmin := porter.RequireAnyRole(provider, "admin", "editor")
handler := editorOrAdmin(mux)
```

### ContextIdentityProvider

Reads identity from the request context using a typed key. Use this when your
auth middleware stores identity on the request context:

```go
type myAuthKey struct{}

provider := porter.ContextIdentityProvider{ContextKey: myAuthKey{}}
```

## Session settings

Porter provides per-session user preferences (theme, layout, etc.) backed by
a `SessionSettingsProvider` repository.

### Setup

```go
// repo implements porter.SessionSettingsProvider
handler := porter.SessionSettingsMiddleware(repo, nil)(mux)
```

When the second argument (`SessionIDFunc`) is nil, porter generates a random
cookie-based session ID automatically.

### Reading settings in handlers

```go
mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
    settings := porter.GetSessionSettings(r)
    tmpl.Execute(w, map[string]any{
        "Theme":  settings.Theme,
        "Layout": settings.Layout,
    })
})
```

### SessionConfig

Optional configuration passed as a variadic argument to
`SessionSettingsMiddleware`:

| Field        | Type           | Default                | Description                        |
|--------------|----------------|------------------------|------------------------------------|
| `CookieName` | `string`      | `"porter_session_id"` | Name of the fallback session cookie. |
| `Logger`     | `*slog.Logger` | `slog.Default()`      | Logger for error reporting.        |

### SessionSettings

The `SessionSettings` struct holds the persisted preferences:

| Field         | Type        | Description                       |
|---------------|-------------|-----------------------------------|
| `SessionUUID` | `string`    | The session identifier.           |
| `Theme`       | `string`    | UI theme (default `"light"`).     |
| `Layout`      | `string`    | UI layout (default `"classic"`).  |
| `UpdatedAt`   | `time.Time` | Last update timestamp.            |
| `ID`          | `int`       | Database row ID.                  |

### SessionSettingsProvider interface

Implement this interface to back session settings with your storage layer
(SQL, Redis, in-memory, etc.):

```go
type SessionSettingsProvider interface {
    GetByUUID(ctx context.Context, uuid string) (*SessionSettings, error)
    Upsert(ctx context.Context, s *SessionSettings) error
    Touch(ctx context.Context, uuid string) error
}
```

### Constants

```go
const (
    DefaultTheme  = "light"
    DefaultLayout = "classic"
    LayoutApp     = "app"
)
```

`NewDefaultSettings(uuid)` returns a `*SessionSettings` populated with these
defaults.

## Context accessors

Porter stores values on the request context and provides type-safe accessor
functions:

| Function              | Returns              | Description                              |
|-----------------------|----------------------|------------------------------------------|
| `GetSessionSettings(r)` | `*SessionSettings` | Session settings from the middleware.    |
| `GetIdentity(r)`      | `Identity`           | Identity set by auth middleware.         |

## With crooner

[Crooner](https://github.com/catgoose/crooner) handles authentication (OIDC,
OAuth2, session management). Porter layers on top for session settings and
authorization. The two libraries share the same interface conventions, so
wiring them together requires no adapters or glue code.

### Session settings with crooner's session ID

Porter's `SessionSettingsMiddleware` accepts an optional `SessionIDFunc` that
returns the session identifier for the current request. When crooner manages
sessions, read the SCS token from the request so that session settings are
tied to the authenticated session rather than a separate cookie:

```go
session := porter.SessionSettingsMiddleware(repo, func(r *http.Request) string {
    cookie, err := r.Cookie(sm.GetCookieName())
    if err != nil || cookie.Value == "" {
        return "" // falls back to porter's random cookie ID
    }
    return cookie.Value
})
handler := session(mux)
```

When the function returns an empty string (no session cookie yet), porter
automatically falls back to a random cookie-based session ID, so
unauthenticated visitors still get session settings.

## Without crooner

For apps that do not need external authentication, porter works standalone:

```go
mux := http.NewServeMux()

// Session settings with auto-generated cookie IDs.
session := porter.SessionSettingsMiddleware(repo, nil)

// Auth middleware (if needed).
auth := porter.RequireAuth(provider)

handler := auth(session(mux))
```

## Architecture

```
+--------------------------------------+
|             HTTP Request             |
+--------------+-----------------------+
               |
       +-------v-------+
       |   crooner      |  "Who are you?"
       |   (optional)   |  OIDC / OAuth2 / session login
       +-------+-------+
               | identity on context
       +-------v-------+
       |   porter       |  "What can you do?"
       |                |  session settings / authorization
       +-------+-------+
               |
       +-------v-------+
       |   handler      |  Application logic
       +---------------+
```

## License

MIT
