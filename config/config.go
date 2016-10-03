package config

import (
	"farm.e-pedion.com/repo/logger"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	path "path/filepath"
	"time"
)

var (
	configuration *Configuration
)

//Setup initializes the package
func Setup() error {
	var cfg string
	flag.StringVar(&cfg, "cfg", "/etc/security/security.yaml", "Security configuration")
	flag.Parse()
	viper.SetConfigName(path.Base(cfg)) // name of config file (without extension)
	viper.SetConfigType(path.Ext(cfg))  // config type
	//viper.AddConfigPath("/etc/appname/")  // path to look for the config file in
	//viper.AddConfigPath("$HOME/.appname") // call multiple times to add many search paths
	viper.AddConfigPath("." + path.Dir(cfg)) // optionally look for config in the working directory
	err := viper.ReadInConfig()              // Find and read the config file
	if err != nil {                          // Handle errors reading the config file
		return fmt.Errorf("config.SetupErr[Message='%s']\n", err)
	}
	return nil
}

//Configuration holds all possible configurations structs
type Configuration struct {
	Version string
	*HandlerConfig
	*ProxyConfig
	*CassandraConfig
	*DBConfig
	*SecurityConfig
	*CacheConfig
	*HTTPConfig
	LoggerConfig *logger.Configuration
}

func (c *Configuration) String() string {
	//return fmt.Sprintf("Configuration[Version=%v ProxyConfig=%v DBConfig=%v SecurityConfig=%v CacheConfig=%v LoggerConfig=%v]", c.Version, c.ProxyConfig, c.DBConfig, c.SecurityConfig, c.CacheConfig, c.LoggerConfig)
	return fmt.Sprintf("Configuration[Version=%v LoggerConfig=%v CassandraConfig=%v]", c.Version, c.LoggerConfig, c.CassandraConfig)
}

//Get returns the configuration struct
func Get() *Configuration {
	if configuration == nil {
		configuration = &Configuration{}
		configuration.Version = fmt.Sprintf("debug-%v", time.Now().UnixNano())
		/*
				flag.StringVar(&configuration.Version, "version", fmt.Sprintf("transientbuild-%v", time.Now().UnixNano()), "Target bind address")

			configuration.HandlerConfig = BindHandlerConfiguration()
			configuration.ProxyConfig = BindProxyConfiguration()
			configuration.DBConfig = BindDBConfiguration()
			configuration.CacheConfig = BindCacheConfiguration()
			configuration.HTTPConfig = BindHTTPConfiguration()
		*/
		configuration.LoggerConfig = GetLoggerConfiguration()
		configuration.CassandraConfig = GetCassandraConfiguration()
	}
	return configuration
}
