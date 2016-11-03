package mongo

import (
	"fmt"
)

//Configuration holds the mongodb connection parameters
type Configuration struct {
	URL      string
	Database string
	Username string
	Password string
}

func (c Configuration) String() string {
	return fmt.Sprintf("mongo.Configuration URL=%v Database=%v Username=%v Password=%v", c.URL, c.Database, c.Username, c.Password)
}
