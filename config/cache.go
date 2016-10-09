package config

import (
	"flag"
	"fmt"
)

var (
	cacheConfig *CacheConfig
)

//CacheConfig holds cache connections parameters
type CacheConfig struct {
	CacheAddress string
}

func (c CacheConfig) String() string {
	return fmt.Sprintf("CacheConfig[CacheAddress=%v]", c.CacheAddress)
}

//BindCacheConfiguration gets and binds, only if necessary, parameters for cache connections
func BindCacheConfiguration() *CacheConfig {
	if cacheConfig == nil {
		cacheConfig = &CacheConfig{}
		flag.StringVar(&cacheConfig.CacheAddress, "cache_address", "127.0.0.1:11211", "Cache target address")
	}
	return cacheConfig
}
