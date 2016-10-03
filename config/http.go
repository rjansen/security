package config

import (
	"flag"
	"fmt"
)

var (
	httpConfig *HTTPConfig
)

//HTTPConfig holds http connections parameters
type HTTPConfig struct {
	RequestTimeout  int
	MaxConnsPerHost int
}

func (c *HTTPConfig) String() string {
	return fmt.Sprintf("HTTPConfig[RequestTimeout=%v MaxConnsPerHost=%v]", c.RequestTimeout, c.MaxConnsPerHost)
}

//BindHTTPConfiguration gets and binds, only if necessary, parameters for http connections
func BindHTTPConfiguration() *HTTPConfig {
	if httpConfig == nil {
		httpConfig = &HTTPConfig{}
		flag.IntVar(&httpConfig.RequestTimeout, "http_request_timeout", 500, "HTTP request timeout in milliseconds")
		flag.IntVar(&httpConfig.MaxConnsPerHost, "http_max_conns_perhost", 256, "HTTP maximum open connections per host")
	}
	return httpConfig
}
