package config

import (
    "fmt"
    "flag"
)

var (
    proxyConfig *ProxyConfig
)

type ProxyConfig struct {
    BindAddress string
    ApiURL string
    WebURL string
}

func (c *ProxyConfig) String() string {
    return fmt.Sprintf("ProxyConfig[BindAddress[%v] ApiURL[%v] WebURL[%v]]", c.BindAddress, c.ApiURL, c.WebURL)
}


func BindProxyConfiguration() *ProxyConfig {
    if proxyConfig == nil {
        proxyConfig = &ProxyConfig{}
        flag.StringVar(&proxyConfig.BindAddress, "bind_address", "127.0.0.1:8000", "Target bind address")
        flag.StringVar(&proxyConfig.ApiURL, "api_url", "http://127.0.0.1:6000", "Api target address")
        flag.StringVar(&proxyConfig.WebURL, "web_url", "http://127.0.0.1:7000", "Web target address")
    }
    return proxyConfig
}

