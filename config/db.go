package config

import (
	"fmt"
)

var (
	dbConfig *DBConfig
)

//DBConfig holds database connections parameters
type DBConfig struct {
	Provider string `mapstructure:"provider"`
	URL      string `mapstructure:"url"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

func (c DBConfig) String() string {
	return fmt.Sprintf("DBConfig Driver=%v URL=%v Username=%v Password=%v", c.Provider, c.URL, c.Username, c.Password)
}
