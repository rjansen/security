package cassandra

import (
	"errors"
	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"fmt"
	"github.com/gocql/gocql"
	"github.com/matryer/resync"
	"time"
)

//pool is a variable to hold the Cassandra Pool
var (
	pool          *CassandraPool
	once          resync.Once
	configuration *Configuration
)

//Configuration holds Cassandra connections parameters
type Configuration struct {
	URL       string        `json:"url" mapstructure:"url"`
	Keyspace  string        `json:"keyspace" mapstructure:"keyspace"`
	Username  string        `json:"username" mapstructure:"username"`
	Password  string        `json:"password" mapstructure:"password"`
	NumConns  int           `json:"numConns" mapstructure:"numConns"`
	KeepAlive time.Duration `json:"keepAliveDuration" mapstructure:"keepAliveDuration"`
}

func (c Configuration) String() string {
	return fmt.Sprintf("cassandra.Configuration URL=%v Keyspace=%v Username=%v Password=%v NumConns=%d KeepAlive=%s",
		c.URL, c.Keyspace, c.Username, c.Password, c.NumConns, c.KeepAlive,
	)
}

//GetPool gets the singleton db pool reference.
//You must call Setup before get the pool reference
func GetPool() (*CassandraPool, error) {
	if pool == nil {
		return nil, errors.New("SetupMustCalled: Message='You must call Setup with a CassandraConfig before get a Cassandrapool reference')")
	}
	return pool, nil
}

//Setup configures a poll for database connections
func Setup() error {
	if err := config.UnmarshalKey("db.cassandra", &configuration); err != nil {
		logger.Info("cassandra.GetConfigErr", logger.Err(err))
		return err
	}
	logger.Info("cassandra.ConfigDriver",
		logger.String("configuration", configuration.String()),
	)
	cluster := gocql.NewCluster(configuration.URL)
	cluster.NumConns = configuration.NumConns
	cluster.SocketKeepalive = configuration.KeepAlive
	cluster.ProtoVersion = 4
	cluster.Keyspace = configuration.Keyspace
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: configuration.Username,
		Password: configuration.Password,
	}

	session, err := cluster.CreateSession()
	if err != nil {
		return fmt.Errorf("cassandra.CreateSessionError message=%v", err.Error())
	}
	pool = &CassandraPool{
		cluster: cluster,
		session: session,
	}
	logger.Info("cassandra.DriverConfigured",
		logger.String("config", configuration.String()),
	)
	return nil
}

//Close close the database pool
func Close() error {
	if pool == nil || pool.cluster == nil {
		return errors.New("SetupMustCalled: Message='You must call Setup with a CassandraBConfig before get a Cassandrapool reference')")
	}
	logger.Info("CloseCassandraSession",
		logger.String("CassandraPool", pool.String()),
	)
	// pool.cluster.Close()
	return nil
}

//CassandraPool controls how new gocql.Session will create and maintained
type CassandraPool struct {
	cluster *gocql.ClusterConfig
	session *gocql.Session
}

func (c CassandraPool) String() string {
	return fmt.Sprintf("CassandraPool Configuration=%s ClusterIsNil=%t SessionIsNil=%t",
		configuration.String(),
		c.cluster == nil,
		c.session == nil,
	)
}

//GetConnection creates and returns a sql.DB reference
func (c *CassandraPool) GetConnection() (*gocql.Session, error) {
	if c == nil || c.session == nil {
		return nil, errors.New("SetupMustCalled: Message='You must call Setup with a CassandraConfig before get a Cassandrapool reference')")
	}
	if c.session.Closed() {
		return nil, fmt.Errorf("cassandra.SessionIsClosedErr")
	}
	logger.Debug("cassandra.GetSession",
		logger.String("Pool", c.String()),
		logger.Bool("SessionIsNil", c.session == nil),
		logger.Bool("SessionIsClosed", c.session.Closed()),
	)
	return c.session, nil
}

//Datasource holds parameterts to create new sql.DB connections
type Datasource struct {
	URL      string
	Keyspace string
	Username string
	Password string
}

//GetDSN retuns a DNS representation of Datasource struct
//DSN format: [username[:password]@][protocol[(address)]]/dbname[?param1=value1&...&paramN=valueN]
func (d *Datasource) GetDSN() string {
	return fmt.Sprintf("%s:%s@%s", d.Username, d.Password, d.URL)
}

//FromDSN fills the connection parameters of this Datasource instance
func (d *Datasource) FromDSN(DSN string) error {
	regex := "(()?(:())@)?()?/()?"
	return fmt.Errorf("NotImplemented: Regex='%v'", regex)
}
