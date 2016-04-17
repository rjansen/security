package config

import (
    "fmt"
    "flag"
)

var (
    securityConfig *SecurityConfig
)

type SecurityConfig struct {
    EncryptCost int
}

func (c *SecurityConfig) String() string {
    return fmt.Sprintf("SecurityConfig[EncryptCost[%v]]", c.EncryptCost)
}

func BindSecurityConfig() *SecurityConfig {
    if securityConfig == nil {
        securityConfig = &SecurityConfig{}
        flag.IntVar(&securityConfig.EncryptCost, "encrypt_cost", 10, "Bcrypt encrypt cost")
    }
    return securityConfig
}

