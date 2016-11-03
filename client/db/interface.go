package db

import (
	"context"
	"fmt"

	"errors"
	"farm.e-pedion.com/repo/security/client/db/cassandra"
)

var (
	ErrInvalidContext = errors.New("The provided Context is invalid")
	dbClientKey       = 1
)

//GetClient reads a dbClient from a context
func GetClient(c context.Context) (cassandra.Client, error) {
	if c == nil {
		return nil, ErrInvalidContext
	}
	dbClient, ok := c.Value(dbClientKey).(cassandra.Client)
	if !ok {
		return nil, fmt.Errorf("ErrInvalidDBClient client=%+v", dbClient)
	}
	return dbClient, nil
}

//SetClient preapres and set a dbClient into context
func SetClient(c context.Context) (context.Context, error) {
	if c == nil {
		return nil, ErrInvalidContext
	}
	return context.WithValue(c, dbClientKey, cassandra.NewClient()), nil
}

//ExecutableFunc is a functions with context olny parameter
type ExecutableFunc func(context.Context) error

//Execute preapres a dbClient and set it inside context to call the provided function
func Execute(execFunc ExecutableFunc) error {
	c, err := SetClient(context.Background())
	if err != nil {
		return err
	}
	return execFunc(c)
}
