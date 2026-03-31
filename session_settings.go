package porter

import "time"

// SessionSettings holds per-session user preferences keyed by a browser UUID
// cookie. The struct is designed to be stored in a database row; the db tags
// match the expected column names.
type SessionSettings struct {
	// SessionUUID is the unique identifier tying these settings to a browser session.
	SessionUUID string `db:"SessionUUID"`

	// Theme is the UI color scheme (e.g. "light", "dark").
	Theme string `db:"Theme"`

	// Layout is the UI layout mode (e.g. "classic", "app").
	Layout string `db:"Layout"`

	// UpdatedAt tracks when the settings were last modified or touched.
	UpdatedAt time.Time `db:"UpdatedAt"`

	// ID is the database primary key.
	ID int `db:"Id"`
}

// Default settings values and layout constants.
const (
	// DefaultTheme is the theme applied to new sessions.
	DefaultTheme = "light"

	// DefaultLayout is the layout applied to new sessions.
	DefaultLayout = "classic"

	// LayoutApp is the alternative "app" layout mode.
	LayoutApp = "app"
)

// NewDefaultSettings returns a SessionSettings with defaults for the given UUID.
func NewDefaultSettings(uuid string) *SessionSettings {
	return &SessionSettings{
		SessionUUID: uuid,
		Theme:       DefaultTheme,
		Layout:      DefaultLayout,
	}
}
