package cassandra

import (
	testify "github.com/stretchr/testify/mock"
)

//NewMockClient creates a new Cassandra Client mock
func NewMockClient() *MockClient {
	return &MockClient{}
}

type MockReader struct {
	testify.Mock
}

func (m *MockReader) QueryOne(query string, fetchFunc func(Fetchable) error, params ...interface{}) error {
	args := m.Called(query, fetchFunc, params)
	return args.Error(0)
}

func (m *MockReader) Query(query string, iterFunc func(Iterable) error, params ...interface{}) error {
	args := m.Called(query, iterFunc, params)
	return args.Error(0)
}

type MockExecutor struct {
	testify.Mock
}

func (m *MockExecutor) Exec(cql string, params ...interface{}) error {
	args := m.Called(cql, params)
	return args.Error(0)
}

type MockClient struct {
	testify.Mock
}

func (m *MockClient) QueryOne(query string, fetchFunc func(Fetchable) error, params ...interface{}) error {
	args := m.Called(query, fetchFunc, params)
	return args.Error(0)
}

func (m *MockClient) Query(query string, iterFunc func(Iterable) error, params ...interface{}) error {
	args := m.Called(query, iterFunc, params)
	return args.Error(0)
}

func (m *MockClient) Exec(cql string, params ...interface{}) error {
	args := m.Called(cql, params)
	return args.Error(0)
}
