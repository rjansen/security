package database

import (
	"errors"
	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"fmt"
	"github.com/gocql/gocql"
)

//pool is a variable to hold the Cassandra Pool
var (
	log  = logger.GetLogger("database")
	pool *CassandraPool
)

//GetPool gets the singleton db pool reference.
//You must call Setup before get the pool reference
func GetPool() (*CassandraPool, error) {
	if pool == nil {
		return nil, errors.New("SetupMustCalled: Message='You must call Setup with a CassandraConfig before get a Cassandrapool reference')")
	}
	return pool, nil
}

//Setup configures a poll for database connections
func Setup(config *config.CassandraConfig) error {
	datasource := Datasource{
		Username: config.Username,
		Password: config.Password,
		URL:      config.URL,
		Keyspace: config.Keyspace,
	}
	pool = &CassandraPool{
		MinCons:    5,
		MaxCons:    10,
		Datasource: datasource,
	}
	log.Infof("ConfigCassandraClient: CassandraPool=%+v", pool)
	cluster := gocql.NewCluster(pool.Datasource.URL)
	cluster.ProtoVersion = 4
	cluster.Keyspace = pool.Datasource.Keyspace
	cluster.Authenticator = gocql.PasswordAuthenticator{
		Username: pool.Datasource.Username,
		Password: pool.Datasource.Password,
	}

	session, err := cluster.CreateSession()
	if err != nil {
		return fmt.Errorf("CreateSessionError: Message=%v", err.Error())
	}
	pool.Session = session
	log.Infof("CassandraClientConfigured: Config=%+v", config)
	return nil
}

//Close close the database pool
func Close() error {
	if pool == nil || pool.Session == nil {
		return errors.New("SetupMustCalled: Message='You must call Setup with a CassandraBConfig before get a Cassandrapool reference')")
	}
	log.Infof("CloseCassandraSession: CassandraPool=%+v", pool)
	pool.Session.Close()
	return nil
}

//CassandraPool controls how new gocql.Session will create and maintained
type CassandraPool struct {
	MinCons int
	MaxCons int
	Datasource
	Session *gocql.Session
}

//GetConnection creates and returns a sql.DB reference
func (c *CassandraPool) GetConnection() (*gocql.Session, error) {
	if c == nil || c.Session == nil {
		return nil, errors.New("SetupMustCalled: Message='You must call Setup with a CassandraConfig before get a Cassandrapool reference')")
	}
	if c.Session.Closed() {
		return nil, errors.New("SessionIdClosed: Message='The Cassandra session is closed'")
	}
	log.Debugf("GetSession: CassandraPool=%+v", c)
	return c.Session, nil
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
