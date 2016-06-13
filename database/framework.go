package database

import (
	"errors"
	"fmt"
	"github.com/gocql/gocql"
	"strings"
)

//Attachable creates a interface for structs do database actions
type Attachable interface {
	SetDB(session *gocql.Session) error
	GetDB() (*gocql.Session, error)
	Attach() error
	Release() error
}

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

//QueryOne executes the single result query with the provided parameters and fetch the result
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

//Query executes the query with the provided parameters and process the results
func (q *QuerySupport) Query(query string, iterFunc func(Iterable) error, params ...interface{}) error {
	if strings.TrimSpace(query) == "" {
		return errors.New("identity.QuerySupport.QueryError: Messages='NilReadQuery")
	}
	if params == nil || len(params) <= 0 {
		return errors.New("identity.QuerySupport.QueryError: Messages='EmptyReadParameters")
	}
	if iterFunc == nil {
		return errors.New("identity.QuerySupport.QueryError: Messages='NilIterFunction")
	}
	q.Attach()
	defer q.Release()
	cqlQuery := q.session.Query(query, params...)
	return iterFunc(cqlQuery)
}

//InsertSupport adds insert capability to the struct
type InsertSupport struct {
	dbObject
}

//Insert exeutes the insert command with the provided parameters
func (i *InsertSupport) Insert(insert string, params ...interface{}) error {
	if strings.TrimSpace(insert) == "" {
		return errors.New("identity.InsertSupport.InsertError: Messages='NilInsertQuery")
	}
	if params == nil || len(params) <= 0 {
		return errors.New("identity.InsertSupport.InsertError: Messages='EmptyInsertParameters")
	}
	i.Attach()
	defer i.Release()
	err := i.session.Query(insert, params...).Exec()
	if err != nil {
		return err
	}
	log.Debug("InsertSupport.Inserted: Message='InsertedSuccessfully'")
	return nil
}

//UpdateSupport adds insert capability to the struct
type UpdateSupport struct {
	dbObject
}

//Update exeutes the update command with the provided parameters
func (u *UpdateSupport) Update(update string, params ...interface{}) error {
	if strings.TrimSpace(update) == "" {
		return errors.New("identity.UpdateSupport.UpdateError: Messages='NilUpdateQuery")
	}
	if params == nil || len(params) <= 0 {
		return errors.New("identity.UpdateSupport.UpdateError: Messages='EmptyUpdateParameters")
	}
	u.Attach()
	defer u.Release()
	err := u.session.Query(update, params...).Exec()
	if err != nil {
		return err
	}
	//TODO: Verify how much records was update
	// rowsUpdated, err := result.RowsAffected()
	// if err != nil {
	// 	log.Printf("identity.UpdateSupport.UpdateGetRowsAffectedEx: Message='%v'", err.Error())
	// } else {
	// 	if rowsUpdated != 1 {
	// 		log.Printf("identity.UpdateSupport.UpdateMultipleEx: Message='%d Records was update for Update=%v and Parameters=%v'", rowsUpdated, update, params)
	// 	}
	// }
	// log.Println("identity.UpdateSupport.Updated: Message='UpdatedSuccessfully'")
	return nil
}

//DeleteSupport adds delete capability to the struct
type DeleteSupport struct {
	dbObject
}

//Delete deletes the DECK record references to Deck
func (d *DeleteSupport) Delete(delete string, params ...interface{}) error {
	if strings.TrimSpace(delete) == "" {
		return errors.New("identity.DeleteSupport.DeleteError: Messages='NilDeleteQuery")
	}
	if params == nil || len(params) <= 0 {
		return errors.New("identity.DeleteSupport.DeleteError: Messages='EmptyDeleteParameters")
	}
	d.Attach()
	defer d.Release()
	err := d.session.Query(delete, params...).Exec()
	if err != nil {
		return err
	}
	//TODO: Verify how much records was delete
	// rowsDeleted, err := result.RowsAffected()
	// if err != nil {
	// 	log.Printf("identity.DeleteSupport.DeleteGetRowsAffectedEx: Message='%v'", err.Error())
	// } else {
	// 	if rowsDeleted != 1 {
	// 		log.Printf("identity.DeleteSupport.DeleteMultipleEx: Message='%d Records was delete for Delete=%v and Parameters=%v'", rowsDeleted, delete, params)
	// 	}
	// }
	return nil
}

//SQLSupport adds sql basic commands support fot the struct
type SQLSupport struct {
	QuerySupport
	InsertSupport
	UpdateSupport
	DeleteSupport
}

//Fetchable supply the gocql.Query.Scan interface for a struct
type Fetchable interface {
	Scan(dest ...interface{}) error
}

//Iterable supply the gocql.Query.Iter interface for a struct
type Iterable interface {
	Iter() *gocql.Iter
}

//Readable provides read actions for a struct
type Readable interface {
	Fetch(fetchable Fetchable) error
	Read() error
}

//Writable provides persistence actions for a struct
type Writable interface {
	Persist() error
	Remove() error
}
