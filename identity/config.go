package identity

import (
	// "flag"
	"fmt"
)

type Configuration struct {
	Proxy    ProxyConfig    `mapstructure:"proxy"`
	Security SecurityConfig `mapstructure:"security"`
}

func (c Configuration) String() string {
	return fmt.Sprintf("identity.Configuration Proxy=%s Security=%s",
		c.Proxy, c.Security,
	)
}

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
	return fmt.Sprintf("identity.ProxyConfig ApiURL=%s WebURL=%s LoginURL=%s FormURI=%s UsernameField=%s PasswordField=%s",
		c.ApiURL, c.WebURL, c.LoginURL, c.FormURI, c.FormUsernameField, c.FormPasswordField,
	)
}

type SecurityConfig struct {
	EncryptCost              int    `mapstructure:"encrypt_cost"`
	CookieName               string `mapstructure:"cookie_name"`
	CookieDomain             string `mapstructure:"cookie_domain"`
	CookiePath               string `mapstructure:"cookie_path"`
	UseCustomSSLCertificate  bool   `mapstructure:"client_use_custom_ssl_certificate"`
	CustomSSLCertificatePath string `mapstructure:"custom_ssl_certificate_path"`
}

func (c SecurityConfig) String() string {
	return fmt.Sprintf("SecurityConfig EncryptCost=%d CookieName=%s CookieDomain=%s CookiePath=%s", c.EncryptCost, c.CookieName, c.CookieDomain, c.CookiePath)
}

// func bindSecurityConfiguration() *SecurityConfig {
// 	if securityConfig == nil {
// 		securityConfig = &SecurityConfig{}
// 		flag.IntVar(&securityConfig.EncryptCost, "encrypt_cost", 10, "Bcrypt encrypt cost")
// 		flag.StringVar(&securityConfig.CookieName, "cookie_name", "FIVECOLORS_ID", "Session Cookie name")
// 		flag.StringVar(&securityConfig.CookieDomain, "cookie_domain", "moon.e-pedion.com", "Session Cookie Domain")
// 		flag.StringVar(&securityConfig.CookiePath, "cookie_path", "/", "Session Cookie Path")
// 		flag.BoolVar(&securityConfig.UseCustomSSLCertificate, "client_use_custom_ssl_certificate", false, "Flag to turn on/off the usage of a custom ssl certificate for http client")
// 		flag.StringVar(&securityConfig.CustomSSLCertificatePath, "custom_ssl_certificate_path", "/Users/raphaeljansen/Apps/Cert/startcom.sha2.root.ca.crt", "Custom SSL Certificate to client connections")
//         securityConfig.CustomSSLCertificate = `
// -----BEGIN CERTIFICATE-----
// MIIF5TCCA82gAwIBAgIQal3D5TtOT9B7aR6l/OxkazANBgkqhkiG9w0BAQsFADB9
// MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMi
// U2VjdXJlIERpZ2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3Rh
// cnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTUxMjE2MDEwMDA1WhcN
// MzAxMjE2MDEwMDA1WjB4MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20g
// THRkLjEpMCcGA1UECxMgU3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
// JjAkBgNVBAMTHVN0YXJ0Q29tIENsYXNzIDEgRFYgU2VydmVyIENBMIIBIjANBgkq
// hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2uz0qohni7BLYmaWv8lEaObCK0ygM86s
// eeN2w9FW4HWvQbQKRYDvy43kFuMmFD4RHkHn1Mk7sijXkJ/F8NH+5Tjbins7tFIC
// ZXd+Qe2ODCMcWbOLoYB54sM514tsZk6m3M4lZi3gmT7ISFiNdKpf/C3dZwasWea+
// dbLpwQWZEcM6oCXmW/6L3kwQAhC0GhJm2rBVrYEDvZq1EK3Bv+g5gAW8DVfusUai
// oyW0wfQdnKtOLv1M4rtezrKtE8T5tjyeKvFqMX93+LYVlT8Vs+sD12s3ncldqEDL
// U89IiBjg6FsbLfM2Ket/3RbfvggfQMPQshipdhrZL8q10jibTlViGQIDAQABo4IB
// ZDCCAWAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEF
// BQcDATASBgNVHRMBAf8ECDAGAQH/AgEAMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6
// Ly9jcmwuc3RhcnRzc2wuY29tL3Nmc2NhLmNybDBmBggrBgEFBQcBAQRaMFgwJAYI
// KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnN0YXJ0c3NsLmNvbTAwBggrBgEFBQcwAoYk
// aHR0cDovL2FpYS5zdGFydHNzbC5jb20vY2VydHMvY2EuY3J0MB0GA1UdDgQWBBTX
// kU4BxLC/+Mhnk0Sc5zP6rZMMrzAfBgNVHSMEGDAWgBROC+8apEBbpRdphzDKNGhD
// 0EGu8jA/BgNVHSAEODA2MDQGBFUdIAAwLDAqBggrBgEFBQcCARYeaHR0cDovL3d3
// dy5zdGFydHNzbC5jb20vcG9saWN5MA0GCSqGSIb3DQEBCwUAA4ICAQCO5z+95Eu6
// gog9K9e7DatQXfeUL8zq1Ycj0HKo3ZvFhRjULAVrMj7JrURtfoZziTDl39gvMDhL
// voN5EFEYQWyre5ySsFgGeZQHIC0zhETILSyAE7JCKaEJ//APnkcQfx458GOuJvi+
// p2JpRxa8Sc/HVJ9HqA687QbbJFFZlUP5IqLtCb8yZVBURd4Nm/+01DXBzomoQPwA
// K3cYl9br6Q+eKmCKPKN6X4IT1gwtwXuca1f3OpZTbUFPdPz1KvP1qCFt+rNieSmO
// BN76Xa9ffzoBByzVdnvk2OHuopmJq/eHF+E3s+GFYT6Oxjrez/lEbBvgEmGyXZOZ
// aj6XeDnBxOIYRODfnZG99cy2q5WtDLHKuiMogJGO89PWaI2jK1Aq5sa0j55jp2Je
// FXbRieKw5CKreCIiNR9MpaffieLgbTcK1BSKjxUZtd7BqJ3x1lvD2jbe7WKqzusZ
// btPhFgrDDsgdw27zQokNYBZZaa1LwYZGZgddiAcLcYkilGobA2wLKk6eYz6VnatD
// dI4aQx6FkHWvKU0e7s/cUym6Px3vXrC4z6woAztC98XaorPO0pkL73P4dKSjnKYY
// rYsqe7BnBGtANf1XaG5Pm8BUWJ9WZAWin6KsJXTo8Nj0G4CRq7dq17LBnCbi9Qmp
// Szc2kuPNbrV8PvbTLIXupfZFFj0d9mpaFg==
// -----END CERTIFICATE-----`
// 	}
// 	return securityConfig
// }
