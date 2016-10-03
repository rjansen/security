package config

import (
	"flag"
	"fmt"
)

var (
	proxyConfig *ProxyConfig
)

type ProxyConfig struct {
	BindAddress       string
	ApiURL            string
	WebURL            string
	LoginURL          string
	UseLoginCallback  bool
	LoginCallbackURL  string
	RedirectURL       string
	FormURI           string
	FormUsernameField string
	FormPasswordField string
}

func (c *ProxyConfig) String() string {
	return fmt.Sprintf("ProxyConfig[BindAddress=%v ApiURL=%v WebURL=%v FormURI=%v UsernameField=%v PasswordField=%v]", c.BindAddress, c.ApiURL, c.WebURL, c.FormURI, c.FormUsernameField, c.FormPasswordField)
}

func BindProxyConfiguration() *ProxyConfig {
	if proxyConfig == nil {
		proxyConfig = &ProxyConfig{}
		flag.StringVar(&proxyConfig.ApiURL, "api_url", "http://127.0.0.1:4000", "Api target address")
		flag.StringVar(&proxyConfig.WebURL, "web_url", "http://127.0.0.1:3000", "Web target address")
		flag.StringVar(&proxyConfig.LoginURL, "login_url", "https://moon.e-pedion.com:8443/fivecolors/auth/login/", "Login page address")
		flag.BoolVar(&proxyConfig.UseLoginCallback, "use_login_callback", true, "Flag to turn on/off the LoginCallback feature")
		flag.StringVar(&proxyConfig.LoginCallbackURL, "login_callback_url", "http://127.0.0.1:4000/player/", "LoginCallback address")
		flag.StringVar(&proxyConfig.RedirectURL, "redirect_url", "https://moon.e-pedion.com:8443/fivecolors/web/", "Login successfully redirect address")
		flag.StringVar(&proxyConfig.FormURI, "form_uri", "/fivecolors/auth/login/", "Form Login target uri")
		flag.StringVar(&proxyConfig.FormUsernameField, "form_username_field", "fivecolors_username", "Form Username field name")
		flag.StringVar(&proxyConfig.FormPasswordField, "form_password_field", "fivecolors_password", "Form Password field name")
	}
	return proxyConfig
}
