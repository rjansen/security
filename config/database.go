package config

import (
    "fmt"
    "flag"
)

var (
    dbConfig *DBConfig
)

//DBConfig holds database connections parameters
type DBConfig struct {
    Driver string
    URL string
    Username string
    Password string
}

func (c *DBConfig) String() string {
    return fmt.Sprintf("DBConfig[Driver=%v URL=%v Username=%v Password=%v]", c.Driver, c.URL, c.Username, c.Password)
}

//BindDBConfiguration gets and binds, only if necessary, parameters for database connections
func BindDBConfiguration() *DBConfig {
    if dbConfig == nil {
        dbConfig = &DBConfig{}
        flag.StringVar(&dbConfig.Driver, "db_driver", "mysql", "Database driver")
        flag.StringVar(&dbConfig.URL, "db_url", "tcp(127.0.0.1:3306)/fivecolors", "Database dsn address")
        flag.StringVar(&dbConfig.Username, "db_username", "fivecolors", "Database username")
        flag.StringVar(&dbConfig.Password, "db_password", "fivecolors", "Database password")
    }
    return dbConfig
}
