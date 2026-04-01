# porter

[![Go Reference](https://pkg.go.dev/badge/github.com/catgoose/porter.svg)](https://pkg.go.dev/github.com/catgoose/porter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![porter](https://raw.githubusercontent.com/catgoose/screenshots/main/porter/porter.png)

Authorization middleware, CSRF protection, and session settings for
[Echo](https://echo.labstack.com). Works with or without an external auth
provider (like [crooner](https://github.com/catgoose/crooner)).

## Install

```bash
go get github.com/catgoose/porter
```

## Quick start

```go
package main

import (
    "github.com/catgoose/porter"
    "github.com/labstack/echo/v4"
)

func main() {
    e := echo.New()

    // CSRF protection with cookie-based token store
    e.Use(porter.CSRF(porter.CookieCSRFStore{}, porter.CSRFConfig{}))

    // Session settings (requires a SessionSettingsProvider implementation)
    e.Use(porter.SessionSettingsMiddleware(repo, nil))

    e.Logger.Fatal(e.Start(":8080"))
}
```

## CSRF protection

The `CSRF` function returns Echo middleware that generates tokens on safe methods
(GET, HEAD, OPTIONS, TRACE) and validates them on unsafe methods (POST, PUT,
DELETE, PATCH). Tokens are read from the `X-CSRF-Token` header first, then the
`_csrf` form value.

### Configuration

```go
e.Use(porter.CSRF(store, porter.CSRFConfig{
    // Paths that skip CSRF validation entirely (login, OAuth callbacks).
    ExemptPaths: []string{"/login", "/callback", "/logout"},

    // Paths that get a fresh token on every GET (one-time-use forms).
    PerRequestPaths: []string{"/transfer"},

    // Rotate the token on every safe request, globally.
    RotatePerRequest: false,
}))
```

### CSRFConfig

| Field              | Type       | Description                                                                 |
|--------------------|------------|-----------------------------------------------------------------------------|
| `ExemptPaths`      | `[]string` | Paths that skip CSRF validation entirely. Prefix matching is applied.       |
| `PerRequestPaths`  | `[]string` | Paths that get a fresh token on every safe request (exact match).           |
| `RotatePerRequest` | `bool`     | When true, rotate the token on every safe request regardless of path.       |

### Reading the token in templates

The middleware sets the token on the echo context under `"csrf_token"`:

```go
e.GET("/form", func(c echo.Context) error {
    token := c.Get("csrf_token").(string)
    return c.Render(http.StatusOK, "form.html", map[string]any{
        "CSRFToken": token,
    })
})
```

In your form:

```html
<form method="POST" action="/submit">
    <input type="hidden" name="_csrf" value="{{.CSRFToken}}">
    <!-- fields -->
</form>
```

### CSRFSessionStore interface

Any session backend that implements `Get` and `Set` can be used as the CSRF
token store:

```go
type CSRFSessionStore interface {
    Get(c echo.Context, key string) (any, error)
    Set(c echo.Context, key string, value any) error
}
```

This is compatible with crooner's session manager out of the box. Crooner's
`SessionManager` has the same `Get` and `Set` signatures, so any crooner
session manager (`*SCSManager`, custom implementations, etc.) satisfies
`CSRFSessionStore` directly -- no wrapper needed.

### CookieCSRFStore

For apps that do not have a server-side session store, `CookieCSRFStore` stores
the CSRF token in an `HttpOnly` cookie named `_csrf`:

```go
e.Use(porter.CSRF(porter.CookieCSRFStore{}, porter.CSRFConfig{}))
```

### Nil store

When the session store is nil, the CSRF middleware is a no-op. This is useful
for conditionally disabling CSRF in development or testing.

## Session settings

Porter provides per-session user preferences (theme, layout, etc.) backed by
a `SessionSettingsProvider` repository.

### Setup

```go
// repo implements porter.SessionSettingsProvider
e.Use(porter.SessionSettingsMiddleware(repo, nil))
```

When the second argument (`SessionIDFunc`) is nil, porter generates a random
cookie-based session ID automatically.

### Reading settings in handlers

```go
e.GET("/dashboard", func(c echo.Context) error {
    settings := porter.GetSessionSettings(c)
    return c.Render(http.StatusOK, "dashboard.html", map[string]any{
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

## With crooner

[Crooner](https://github.com/catgoose/crooner) handles authentication (OIDC,
OAuth2, session management). Porter layers on top for CSRF, session settings,
and authorization. The two libraries share the same interface conventions, so
wiring them together requires no adapters or glue code.

### CSRF with crooner's session manager

```go
sm, scsMgr, err := crooner.NewSCSManager(
    crooner.WithPersistentCookieName(secret, "myapp"),
    crooner.WithLifetime(12 * time.Hour),
    crooner.WithStore(redisStore),
)
if err != nil {
    log.Fatal(err)
}

// sm satisfies porter.CSRFSessionStore -- pass it directly.
e.Use(porter.CSRF(sm, porter.CSRFConfig{
    ExemptPaths: []string{"/login", "/callback", "/logout"},
}))
```

### Session settings with crooner's session ID

Porter's `SessionSettingsMiddleware` accepts an optional `SessionIDFunc` that
returns the session identifier for the current request. When crooner manages
sessions, read the SCS token from the request so that session settings are
tied to the authenticated session rather than a separate cookie:

```go
e.Use(porter.SessionSettingsMiddleware(repo, func(c echo.Context) string {
    cookie, err := c.Cookie(sm.GetCookieName())
    if err != nil || cookie.Value == "" {
        return "" // falls back to porter's random cookie ID
    }
    return cookie.Value
}))
```

When the function returns an empty string (no session cookie yet), porter
automatically falls back to a random cookie-based session ID, so
unauthenticated visitors still get session settings.

## Without crooner

For apps that do not need external authentication, porter works standalone:

```go
e := echo.New()

// CSRF with the built-in cookie store.
e.Use(porter.CSRF(porter.CookieCSRFStore{}, porter.CSRFConfig{}))

// Session settings with auto-generated cookie IDs.
e.Use(porter.SessionSettingsMiddleware(repo, nil))
```

## Architecture

```
┌──────────────────────────────────────┐
│             HTTP Request             │
└──────────────┬───────────────────────┘
               │
       ┌───────▼───────┐
       │   crooner      │  "Who are you?"
       │   (optional)   │  OIDC / OAuth2 / session login
       └───────┬───────┘
               │ identity on context
       ┌───────▼───────┐
       │   porter       │  "What can you do?"
       │                │  CSRF · session settings
       └───────┬───────┘
               │
       ┌───────▼───────┐
       │   handler      │  Application logic
       └───────────────┘
```

## License

MIT
