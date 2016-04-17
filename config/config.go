package config

import (
    "fmt"
    "os"
    "flag"
    "time"
    "github.com/vharitonsky/iniflags"
)

var (
    configuration *Configuration
)

type Configuration struct {
    Version string
    *ProxyConfig
    *DBConfig
    *SecurityConfig
}

func (c *Configuration) String() string {
    return fmt.Sprintf("Configuration[Version[%v] ProxyConfig[%+v] DBConfig[%+v] SecurityConfig[%v]]", c.Version, c.ProxyConfig, c.DBConfig, c.SecurityConfig)
}

func BindConfiguration() *Configuration {
    if configuration == nil {
        configuration = &Configuration{}
        flag.StringVar(&configuration.Version, "version", fmt.Sprintf("transientbuild-%v", time.Now().UnixNano()), "Target bind address")

        configuration.ProxyConfig = BindProxyConfiguration()
        configuration.DBConfig = BindDBConfiguration()
    }
    return configuration
}

func Init() {
    iniflags.Parse()
}

// Print error, usage and exit with code
func printErrorUsageAndExitWithCode(err string, code int) {
    fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
    printUsage()
    os.Exit(code)
}

// Print command line help
func printUsage() {
    fmt.Fprintf(os.Stderr, "Usage: %s [flags] [CONFIG]\n", os.Args[0])
    fmt.Fprintf(os.Stderr, "\nFlags:\n")
    flag.PrintDefaults()
    fmt.Fprintf(os.Stderr, "\nArguments:\n")
    fmt.Fprintf(os.Stderr, "  CONFIG: Config file path\n")
    fmt.Fprintf(os.Stderr, "\n")
}

