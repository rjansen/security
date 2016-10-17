package config

import (
	//"flag"
	"fmt"
)

//CassandraConfig holds Cassandra connections parameters
type CassandraConfig struct {
	URL      string `mapstructure:"url"`
	Keyspace string `mapstructure:"keyspace"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

func (c CassandraConfig) String() string {
	return fmt.Sprintf("CassandraConfig URL=%v Keyspace=%v Username=%v Password=%v", c.URL, c.Keyspace, c.Username, c.Password)
}
