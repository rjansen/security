package cassandra

import (
	"github.com/gocql/gocql"
)

//Attachable creates a interface for structs do database actions
type Attachable interface {
	SetDB(session *gocql.Session) error
	GetDB() (*gocql.Session, error)
	Attach() error
	Release() error
}

//Fetchable supply the gocql.Query.Scan interface for a struct
type Fetchable interface {
	Scan(dest ...interface{}) error
}

//Iterable supply the gocql.Query.Iter interface for a struct
type Iterable interface {
	Iter() *gocql.Iter
}

//Reader provides cassadra read actions
type Reader interface {
	QueryOne(query string, fetchFunc func(Fetchable) error, params ...interface{}) error
	Query(query string, iterFunc func(Iterable) error, params ...interface{}) error
}

//Executor provides cassandra exec supports
type Executor interface {
	Exec(cql string, params ...interface{}) error
}

//Client adds full cassandra supports
type Client interface {
	Reader
	Executor
}

//Readable provides read actions for a struct
type Readable interface {
	Reader
	Fetch(fetchable Fetchable) error
	Iter(iterable Iterable) error
	Read() error
	//ReadExample() ([]Readable, error)
}

//Writable provides persistence actions for a struct
type Writable interface {
	Executor
	Create() error
	Update() error
	Delete() error
}
