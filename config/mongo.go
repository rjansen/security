package config

import (
	"fmt"
)

//MongoConfig holds the mongodb connection parameters
type MongoConfig struct {
	URL      string
	Database string
	Username string
	Password string
}

func (c MongoConfig) String() string {
	return fmt.Sprintf("MongoConfig URL=%v Database=%v Username=%v Password=%v", c.URL, c.Database, c.Username, c.Password)
}
