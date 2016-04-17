package database

import (
    "database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
)

//JSONSerializable provides to a struct json external representation
type JSONSerializable interface {
	Marshal() ([]byte, error)
    //Marshal(writer io.Writer) error
	Unmarshal(reader io.Reader) error
}

//JSONObject adds support to marshall and unmarshall with JSON data type 
type JSONObject struct {
}

//Marshal writes a json representation of Expansion
func (j *JSONObject) Marshal() ([]byte, error) {
	return json.Marshal(j)
}

// //Marshal reads a json representation of Expansion
// func (j *JSONObject) Marshal(writer io.Writer) error {
// 	return json.NewEncoder(writer).Encode(&j)
// }

//Unmarshal reads a json representation of Expansion
func (j *JSONObject) Unmarshal(reader io.Reader) error {
	return json.NewDecoder(reader).Decode(&j)
}

//Attachable creates a interface for structs do database actions
type Attachable interface {
	SetDB(db *sql.DB) error
	GetDB() (*sql.DB, error)
	Attach() error
    Release() error
}

type dbObject struct {
    //db is a transient pointer to database connection
	db *sql.DB
}

//SetDB attachs a database connection to Card
func (d *dbObject) SetDB(db *sql.DB) error {
	if db == nil {
		return errors.New("NullDBReferenceError: Message='The db parameter is required'")
	}
	d.db = db
	return nil
}

//GetDB returns the Card attached connection
func (d *dbObject) GetDB() (*sql.DB, error) {
	if d.db == nil {
		return nil, errors.New("NotAttachedError: Message='The db context is null'")
	}
	return d.db, nil
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
	row := q.db.QueryRow(query, params)
	return fetchFunc(row)
}

//Query executes the query with the provided parameters and process the results
func (q *QuerySupport) Query(query string, fetchFunc func(*sql.Rows) error, params ...interface{}) error {
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
	rows, err := q.db.Query(query, params)
    if err != nil {
        return err
    }
	return fetchFunc(rows)
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
    _, err := i.db.Exec(insert, params)
    if err != nil {
        return err
    }
    log.Println("identity.InsertSupport.Inserted: Message='InsertedSuccessfully'")
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
    result, err := u.db.Exec(update, params)
    if err != nil {
        return err
    }
    rowsUpdated, err := result.RowsAffected()
    if err != nil {
        log.Printf("identity.UpdateSupport.UpdateGetRowsAffectedEx: Message='%v'", err.Error())
    } else {
        if rowsUpdated != 1 {
            log.Printf("identity.UpdateSupport.UpdateMultipleEx: Message='%d Records was update for Update=%v and Parameters=%v'", rowsUpdated, update, params)
        }
    }
    log.Println("identity.UpdateSupport.Updated: Message='UpdatedSuccessfully'")
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
	result, err := d.db.Exec(delete, params)
	if err != nil {
		return err
	}
	rowsDeleted, err := result.RowsAffected()
	if err != nil {
		log.Printf("identity.DeleteSupport.DeleteGetRowsAffectedEx: Message='%v'", err.Error())
	} else {
		if rowsDeleted != 1 {
			log.Printf("identity.DeleteSupport.DeleteMultipleEx: Message='%d Records was delete for Delete=%v and Parameters=%v'", rowsDeleted, delete, params)
		}
	}
	return nil
}

//SQLSupport adds sql basic commands support fot the struct
type SQLSupport struct {
    QuerySupport
    InsertSupport
    UpdateSupport
    DeleteSupport
}

//Fetchable supply the sql.Scan interface for a struct
type Fetchable interface {
	Scan(dest ...interface{}) error
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
