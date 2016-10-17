package config

import (
	"fmt"
)

//HandlerConfig holds http handler parameters
type HandlerConfig struct {
	Version     string `mapstructure:"version"`
	BindAddress string `mapstructure:"bind"`
}

func (h HandlerConfig) String() string {
	return fmt.Sprintf("HandlerConfig Version=%v BindAddress=%v", h.Version, h.BindAddress)
}
