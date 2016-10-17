package config

import (
	"fmt"
)

type ProxyConfig struct {
	ApiURL            string `mapstructure:"api_url"`
	WebURL            string `mapstructure:"web_url"`
	LoginURL          string `mapstructure:"login_url"`
	UseLoginCallback  bool   `mapstructure:"use_login_callback"`
	LoginCallbackURL  string `mapstructure:"login_callback_url"`
	RedirectURL       string `mapstructure:"redirect_url"`
	FormURI           string `mapstructure:"form_uri"`
	FormUsernameField string `mapstructure:"form_username_field"`
	FormPasswordField string `mapstructure:"form_password_field"`
}

func (c ProxyConfig) String() string {
	return fmt.Sprintf("ProxyConfig ApiURL=%s WebURL=%s LoginURL=%s FormURI=%s UsernameField=%s PasswordField=%s",
		c.ApiURL, c.WebURL, c.LoginURL, c.FormURI, c.FormUsernameField, c.FormPasswordField,
	)
}
