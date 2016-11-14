package config

import (
	"farm.e-pedion.com/repo/cache/memcached"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/persistence/cassandra"
	"farm.e-pedion.com/repo/security/client/http"
	"fmt"
)

var (
	Config *Configuration
)

//Configuration holds all possible configurations structs
type Configuration struct {
	Version     string                  `mapstructure:"version"`
	Environment string                  `mapstructure:"environment"`
	Logger      logger.Configuration    `mapstructure:"logger"`
	Memcached   memcached.Configuration `mapstructure:"memcached"`
	Cassandra   cassandra.Configuration `mapstructure:"cassandra"`
	HTTP        http.Configuration      `mapstrucure:"http"`
	Security    SecurityConfig          `mapstrucure:"security"`
	Handler     HandlerConfig           `mapstructure:"handler"`
	Proxy       ProxyConfig             `mapstrucure:"proxy"`
}

func (c Configuration) String() string {
	//return fmt.Sprintf("Configuration[Version=%v ProxyConfig=%v DBConfig=%v SecurityConfig=%v CacheConfig=%v LoggerConfig=%v]", c.Version, c.ProxyConfig, c.DBConfig, c.SecurityConfig, c.CacheConfig, c.LoggerConfig)
	return fmt.Sprintf("Configuration Version=%s Environment=%s Logger=%s Memcached=%s Cassandra=%s HTTP=%s Security=%s Handler=%s Proxy=%s",
		c.Version, c.Environment,
		c.Logger.String(),
		c.Memcached.String(),
		c.Cassandra.String(),
		c.HTTP.String(),
		c.Security.String(),
		c.Handler.String(),
		c.Proxy.String(),
	)
}

func Setup(cfg *Configuration) error {
	Config = cfg
	return nil
}
