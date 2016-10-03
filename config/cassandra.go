package config

import (
	//"flag"
	"fmt"
	"github.com/spf13/viper"
)

var (
	cassandraConfig *CassandraConfig
)

//CassandraConfig holds Cassandra connections parameters
type CassandraConfig struct {
	URL      string `mapstructure:"url"`
	Keyspace string `mapstructure:"keyspace"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

func (c *CassandraConfig) String() string {
	return fmt.Sprintf("CassandraConfig[URL=%v Keyspace=%v Username=%v Password=%v]", c.URL, c.Keyspace, c.Username, c.Password)
}

//GetCassandraConfiguration gets and binds, only if necessary, parameters for Cassandra connections
func GetCassandraConfiguration() *CassandraConfig {
	if cassandraConfig == nil {
		cassandraConfig = &CassandraConfig{}
		if err := viper.Sub("cassandra").Unmarshal(cassandraConfig); err != nil {
			panic(err)
		}
		fmt.Printf("GetCassandraConfig=%v\n", cassandraConfig)
		/*
			flag.StringVar(&cassandraConfig.URL, "cassandra_url", "127.0.0.1", "Cassandra url address")
			flag.StringVar(&cassandraConfig.Keyspace, "cassandra_keyspace", "fivecolors", "Cassandra keyspace")
			flag.StringVar(&cassandraConfig.Username, "cassandra_username", "fivecolors", "Cassandra username")
			flag.StringVar(&cassandraConfig.Password, "cassandra_password", "fivecolors", "Cassandra password")
		*/
	}
	return cassandraConfig
}
