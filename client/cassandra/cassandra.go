package cassandra

import (
	"errors"
	"farm.e-pedion.com/repo/logger"
	"fmt"
	"github.com/gocql/gocql"
	"strings"
)

type dbObject struct {
	//session is a transient pointer to database connection
	session *gocql.Session
}

//SetDB attachs a database connection to Card
func (d *dbObject) SetDB(session *gocql.Session) error {
	if session == nil {
		return errors.New("NullDBReferenceError: Message='The db parameter is required'")
	}
	d.session = session
	return nil
}

//GetDB returns the Card attached connection
func (d *dbObject) GetDB() (*gocql.Session, error) {
	if d.session == nil {
		return nil, errors.New("NotAttachedError: Message='The cassandra session is null'")
	}
	return d.session, nil
}

//Attach binds a new database connection to Card reference
func (d *dbObject) Attach() error {
	if _, err := d.GetDB(); err != nil {
		tempDb, err := pool.GetConnection()
		if err != nil {
			return fmt.Errorf("databse.dbObject.AttachError: Messages='%v'", err.Error())
		}
		return d.SetDB(tempDb)
	}
	return nil
}

func (d *dbObject) Release() error {
	return d.SetDB(nil)
}

//QuerySupport adds query capability to the struct
type QuerySupport struct {
	dbObject
}

//QueryOne executes the single result cql query with the provided parameters and fetch the result
func (q *QuerySupport) QueryOne(query string, fetchFunc func(Fetchable) error, params ...interface{}) error {
	if strings.TrimSpace(query) == "" {
		return errors.New("identity.QuerySupport.QueryError: Messages='NilReadQuery")
	}
	if params == nil || len(params) <= 0 {
		return errors.New("identity.QuerySupport.QueryError: Messages='EmptyReadParameters")
	}
	if fetchFunc == nil {
		return errors.New("identity.QuerySupport.QueryError: Messages='NilFetchFunction")
	}
	q.Attach()
	defer q.Release()
	cqlQuery := q.session.Query(query, params...).Consistency(gocql.One)
	return fetchFunc(cqlQuery)
}

//Query executes the cql query with the provided parameters and process the results
func (q *QuerySupport) Query(query string, iterFunc func(Iterable) error, params ...interface{}) error {
	if strings.TrimSpace(query) == "" {
		return errors.New("QueryError[Messages='EmptyCQLQuery']")
	}
	if params == nil || len(params) <= 0 {
		return errors.New("QueryError[Messages='EmptyQueryParameters']")
	}
	if iterFunc == nil {
		return errors.New("QueryError[Messages='NilIterFunc']")
	}
	q.Attach()
	defer q.Release()
	cqlQuery := q.session.Query(query, params...)
	return iterFunc(cqlQuery)
}

//ExecSupport adds cql exec capability to the struct
type ExecSupport struct {
	dbObject
}

//Exec exeutes the command with the provided parameters
func (i *ExecSupport) Exec(cql string, params ...interface{}) error {
	if strings.TrimSpace(cql) == "" {
		return errors.New("ExecError[Messages='NilCQLQuery']")
	}
	if params == nil || len(params) <= 0 {
		return errors.New("ExecParametersLenInvalid[Messages='EmptyExecParameters']")
	}
	i.Attach()
	defer i.Release()
	err := i.session.Query(cql, params...).Exec()
	if err != nil {
		log.Error("CQLExecutionFalied",
			logger.String("CQL", cql),
			logger.Struct("Parameters", params),
		)
		return err
	}
	log.Debug("CQLExecutedSuccessfully",
		logger.String("CQL", cql),
		logger.Struct("Parameters", params),
	)
	return nil
}

//NewClient creates a new instance of the CQLClient
func NewClient() Client {
	return &CQLClient{
		QuerySupport: QuerySupport{},
		ExecSupport:  ExecSupport{},
	}
}

//CQLClient adds full query and exec support fot the struct
type CQLClient struct {
	QuerySupport
	ExecSupport
}
