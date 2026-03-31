# porter

Authorization middleware, CSRF protection, and session settings for
[Echo](https://echo.labstack.com). Works with or without an external auth
provider (like [crooner](https://github.com/catgoose/crooner)).

## Install

```bash
go get github.com/catgoose/porter
```

## CSRF Protection

Porter ships a session-backed CSRF middleware. Any session store that satisfies
`CSRFSessionStore` can hold the token -- crooner's `SessionManager`, a
cookie-based store, or your own implementation.

### Using the built-in cookie store

```go
e := echo.New()

e.Use(porter.CSRF(porter.CookieCSRFStore{}, porter.CSRFConfig{}))
```

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

The middleware accepts the token from an `X-CSRF-Token` header or a `_csrf`
form value.

## Session Settings

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

## With Crooner

[Crooner](https://github.com/catgoose/crooner) handles authentication (OIDC,
OAuth2, session management). Porter layers on top for CSRF, session settings,
and authorization. The two libraries share the same interface conventions, so
wiring them together requires no adapters or glue code.

### Crooner's SessionManager satisfies CSRFSessionStore

Porter's CSRF middleware needs a `CSRFSessionStore`:

```go
type CSRFSessionStore interface {
    Get(c echo.Context, key string) (any, error)
    Set(c echo.Context, key string, value any) error
}
```

Crooner's `SessionManager` interface has the same `Get` and `Set` signatures,
so any crooner session manager (`*SCSManager`, custom implementations, etc.)
satisfies `CSRFSessionStore` directly -- no wrapper needed:

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

Both crooner and porter use the same session key (`"csrf_token"`) for the
token, so tokens created by crooner's callback handler are validated by
porter's CSRF middleware without any extra configuration.

### Session settings with crooner's session ID

Porter's `SessionSettingsMiddleware` accepts an optional `SessionIDFunc` that
returns the session identifier for the current request. When crooner manages
sessions, read the SCS token from the request so that session settings are
tied to the authenticated session rather than a separate cookie:

```go
// Read the session token that SCS set on the request.
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

### Bridging crooner's user info into porter's Identity

Crooner stores the authenticated user in the session under the `"user"` key
(and optionally additional claims via `SessionValueClaims`). Porter's
authorization middleware expects an `IdentityProvider` that returns a
`porter.Identity`.

Use `ContextIdentityProvider` with a small middleware that reads from
crooner's session and sets the identity on the context:

```go
// CroonerIdentityMiddleware reads the user and roles from crooner's session
// and sets a porter.Identity on the echo context.
func CroonerIdentityMiddleware(sm crooner.SessionManager) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            user, err := crooner.GetString(sm, c, crooner.SessionKeyUser)
            if err != nil || user == "" {
                return next(c) // no session user -- skip
            }

            // Read roles if stored via SessionValueClaims (e.g. "roles" claim).
            var roles []string
            if val, err := sm.Get(c, "roles"); err == nil {
                if r, ok := val.([]string); ok {
                    roles = r
                }
            }

            c.Set("porter.user_identity", porter.SimpleIdentity{
                ID:       user,
                RoleList: roles,
            })
            return next(c)
        }
    }
}
```

Then wire porter's authorization middleware with `ContextIdentityProvider`
pointing at the same context key:

```go
idProvider := porter.ContextIdentityProvider{
    ContextKey: "porter.user_identity",
}

// Protect all /admin routes -- requires authentication + "admin" role.
admin := e.Group("/admin",
    porter.RequireRole(idProvider, "admin"),
)
```

### Complete wiring example

```go
package main

import (
    "log"
    "time"

    "github.com/catgoose/crooner"
    "github.com/catgoose/porter"
    "github.com/labstack/echo/v4"
)

func main() {
    e := echo.New()

    // -- crooner: session + OIDC auth --

    sm, scsMgr, err := crooner.NewSCSManager(
        crooner.WithPersistentCookieName("secret", "myapp"),
        crooner.WithLifetime(12 * time.Hour),
    )
    if err != nil {
        log.Fatal(err)
    }
    e.Use(echo.WrapMiddleware(scsMgr.LoadAndSave))

    // crooner.NewAuthConfig sets up /login, /callback, /logout and
    // the RequireAuth middleware that redirects unauthenticated users.
    // See crooner's README for full AuthConfigParams.

    // -- porter: CSRF --

    // sm satisfies porter.CSRFSessionStore directly.
    e.Use(porter.CSRF(sm, porter.CSRFConfig{
        ExemptPaths: []string{"/login", "/callback", "/logout"},
    }))

    // -- porter: session settings --

    // repo implements porter.SessionSettingsProvider (backed by your DB).
    var repo porter.SessionSettingsProvider
    e.Use(porter.SessionSettingsMiddleware(repo, func(c echo.Context) string {
        cookie, err := c.Cookie(sm.GetCookieName())
        if err != nil || cookie.Value == "" {
            return ""
        }
        return cookie.Value
    }))

    // -- porter: authorization --

    // Bridge crooner's session user into porter's Identity.
    e.Use(CroonerIdentityMiddleware(sm))

    idProvider := porter.ContextIdentityProvider{
        ContextKey: "porter.user_identity",
    }

    // Public routes.
    e.GET("/", homeHandler)

    // Authenticated routes.
    e.GET("/dashboard", dashboardHandler,
        porter.RequireAuth(idProvider),
    )

    // Role-protected routes.
    admin := e.Group("/admin",
        porter.RequireRole(idProvider, "admin"),
    )
    admin.GET("", adminHandler)

    e.Logger.Fatal(e.Start(":8080"))
}

// CroonerIdentityMiddleware reads the user and roles from crooner's session
// and sets a porter.Identity on the echo context.
func CroonerIdentityMiddleware(sm crooner.SessionManager) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            user, err := crooner.GetString(sm, c, crooner.SessionKeyUser)
            if err != nil || user == "" {
                return next(c)
            }
            var roles []string
            if val, err := sm.Get(c, "roles"); err == nil {
                if r, ok := val.([]string); ok {
                    roles = r
                }
            }
            c.Set("porter.user_identity", porter.SimpleIdentity{
                ID:       user,
                RoleList: roles,
            })
            return next(c)
        }
    }
}

func homeHandler(c echo.Context) error      { return c.String(200, "home") }
func dashboardHandler(c echo.Context) error  { return c.String(200, "dashboard") }
func adminHandler(c echo.Context) error      { return c.String(200, "admin") }
```

## Without Crooner

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
       │                │  CSRF · session settings · authorization
       └───────┬───────┘
               │
       ┌───────▼───────┐
       │   handler      │  Application logic
       └───────────────┘
```

## License

MIT
