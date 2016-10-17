package config

import (
	"fmt"
)

//HTTPConfig holds http connections parameters
type HTTPConfig struct {
	RequestTimeout  int `mapstructure:"request_timeout"`
	MaxConnsPerHost int `mapstructure:"max_conns_perhost"`
}

func (c HTTPConfig) String() string {
	return fmt.Sprintf("HTTPConfig RequestTimeout=%d MaxConnsPerHost=%d", c.RequestTimeout, c.MaxConnsPerHost)
}
