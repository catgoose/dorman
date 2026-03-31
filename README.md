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
OAuth2, session management). Porter layers on top for CSRF and session
settings.

### Wiring CSRF with crooner's session manager

Crooner's `SessionManager` already satisfies `CSRFSessionStore`:

```go
sm := crooner.NewSessionManager(...)

// Use crooner's session manager as the CSRF token store.
e.Use(porter.CSRF(sm, porter.CSRFConfig{
    ExemptPaths: []string{"/login", "/callback", "/logout"},
}))
```

### Wiring session settings with crooner's session ID

```go
// Use crooner's session token as the session ID.
e.Use(porter.SessionSettingsMiddleware(repo, func(c echo.Context) string {
    return crooner.SessionID(c)
}))
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
