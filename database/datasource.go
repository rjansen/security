package database

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"farm.e-pedion.com/repo/security/config"
)

//Pool is a variable to hold the Database Pool
var (
	pool *DBPool
)

//GetPool gets the singleton db pool reference.
//You must call Setup before get the pool reference
func GetPool() (*DBPool, error) {
	if pool == nil {
		return nil, errors.New("SetupMustCalled: Message='You must call Setup with a DBConfig before get a DBpool reference')")
	}
	return pool, nil
}

//Setup configures a poll for database connections
func Setup(config *config.DBConfig) error {
	datasource := Datasource{
		Driver:   config.Driver,
		Username: config.Username,
		Password: config.Password,
		URL:      config.URL,
	}
	pool = &DBPool{
		MinCons:    5,
		MaxCons:    10,
		Datasource: datasource,
	}
	log.Printf("data.OpenConnection: DBPool=%+v", pool)
	conn, err := sql.Open(pool.Datasource.Driver, pool.Datasource.GetDSN())
	if err != nil {
		return fmt.Errorf("GetConnectionError: Cause=%v", err.Error())
	}
	pool.Connection = conn
	log.Printf("data.Setted: Config=%+v", config)
    return nil
}

//Close close the database pool
func Close() error {
	if pool == nil || pool.Connection == nil {
		return errors.New("SetupMustCalled: Message='You must call Setup with a DBConfig before get a DBpool reference')")
	}
	log.Printf("data.CloseConnection: DBPool=%+v", pool)
	return pool.Connection.Close()
}

//DBPool controls how new sql.DB will create and maintained
type DBPool struct {
	MinCons int
	MaxCons int
	Datasource
	Connection *sql.DB
}

//GetConnection creates and returns a sql.DB reference
func (d *DBPool) GetConnection() (*sql.DB, error) {
	if d == nil || d.Connection == nil {
		return nil, errors.New("SetupMustCalled: Message='You must call Setup with a DBConfig before get a DBpool reference')")
	}
    if err := d.Connection.Ping(); err != nil {
        return nil, err
    }
	log.Printf("data.GetConnection: DBPool=%+v", d)
	return d.Connection, nil
}
 
//Datasource holds parameterts to create new sql.DB connections
type Datasource struct {
	Driver   string
	URL      string
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
