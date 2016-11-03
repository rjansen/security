package config

import (
	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/db/cassandra"
	"farm.e-pedion.com/repo/security/client/http"
	"flag"
	"fmt"
	"github.com/spf13/viper"
	path "path/filepath"
	"strings"
	"sync"
)

var (
	once          sync.Once
	configuration *Configuration
)

//Setup initializes the package
func Setup() error {
	var cfg string
	flag.StringVar(&cfg, "cfg", "./etc/security/security.yaml", "Security configuration")
	flag.Parse()
	configExt := path.Ext(cfg)
	configName := strings.TrimSuffix(path.Base(cfg), configExt)
	configType := configExt[1:]
	configPath := path.Dir(cfg)
	fmt.Printf("ViperSetup[Name=%v Type=%v Path=%v Cfg=%v]\n", configName, configType, configPath, cfg)
	viper.SetConfigName(configName) // name of config file (without extension)
	viper.SetConfigType(configType) // config type
	viper.AddConfigPath(configPath) // optionally look for config in the working directory
	//viper.AddConfigPath("/etc/appname/")  // path to look for the config file in
	//viper.AddConfigPath("$HOME/.appname") // call multiple times to add many search paths
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		return fmt.Errorf("config.SetupErr[Cfg=%v Message='%s']\n", cfg, err)
	}
	return nil
}

//Configuration holds all possible configurations structs
type Configuration struct {
	Version     string                  `mapstructure:"version"`
	Environment string                  `mapstructure:"environment"`
	Logger      logger.Configuration    `mapstructure:"logger"`
	Cache       cache.Configuration     `mapstructure:"cache"`
	Cassandra   cassandra.Configuration `mapstructure:"cassandra"`
	HTTP        http.Configuration      `mapstrucure:"http"`
	Security    SecurityConfig          `mapstrucure:"security"`
	Handler     HandlerConfig           `mapstructure:"handler"`
	Proxy       ProxyConfig             `mapstrucure:"proxy"`
}

func (c Configuration) String() string {
	//return fmt.Sprintf("Configuration[Version=%v ProxyConfig=%v DBConfig=%v SecurityConfig=%v CacheConfig=%v LoggerConfig=%v]", c.Version, c.ProxyConfig, c.DBConfig, c.SecurityConfig, c.CacheConfig, c.LoggerConfig)
	return fmt.Sprintf("Configuration Version=%s Environment=%s Logger=%s Cache=%s Cassandra=%s HTTP=%s Security=%s Handler=%s Proxy=%s",
		c.Version, c.Environment,
		c.Logger.String(),
		c.Cache.String(),
		c.Cassandra.String(),
		c.HTTP.String(),
		c.Security.String(),
		c.Handler.String(),
		c.Proxy.String(),
	)
}

//Get returns the configuration struct
func Get() *Configuration {
	once.Do(func() {
		/*
			configuration.Version = fmt.Sprintf("debug-%v", time.Now().UnixNano())
					flag.StringVar(&configuration.Version, "version", fmt.Sprintf("transientbuild-%v", time.Now().UnixNano()), "Target bind address")

				configuration.HandlerConfig = BindHandlerConfiguration()
				configuration.ProxyConfig = BindProxyConfiguration()
				configuration.DBConfig = BindDBConfiguration()
				configuration.CacheConfig = BindCacheConfiguration()
				configuration.HTTPConfig = BindHTTPConfiguration()
		*/
		configuration = &Configuration{}
		if err := viper.Unmarshal(configuration); err != nil {
			panic(err)
		}
		/*
			loggerConfig := &logger.Configuration{}
			fmt.Printf("Viper.Logger=%+v\n", viper.Get("logger"))
			if err := viper.Sub("logger").Unmarshal(loggerConfig); err != nil {
				panic(err)
			}
			fmt.Printf("GetLoggerConfig=%v\n", loggerConfig)
			configuration.Logger = loggerConfig

			cassandraConfig := &CassandraConfig{}
			fmt.Printf("Viper.Cassandra=%+v\n", viper.Get("cassandra"))
			if err := viper.Sub("cassandra").Unmarshal(cassandraConfig); err != nil {
				panic(err)
			}
			fmt.Printf("GetCassandraConfig=%v\n", cassandraConfig)
			configuration.Cassandra = cassandraConfig

			handlerConfig := &HandlerConfig{}
			fmt.Printf("Viper.Handler=%+v\n", viper.Get("handler"))
			if err := viper.Sub("handler").Unmarshal(handlerConfig); err != nil {
				panic(err)
			}
			configuration.Handler = handlerConfig
			fmt.Printf("GetHandlerConfig=%v\n", handlerConfig)
		*/
	})
	return configuration
}
