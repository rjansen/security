package data

import (
	"errors"
	"farm.e-pedion.com/repo/security/client/cassandra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestCreateLoginSuccess(t *testing.T) {
	mockCQLClient := cassandra.NewMockClient()
	mockCQLClient.On("Exec", mock.Anything, mock.Anything).Return(nil)

	login := &Login{
		Client:   mockCQLClient,
		Username: "createLoginTest",
		Name:     "Create Login Success Test",
		Password: "123mock321",
		Roles:    []string{"role1", "role2"},
	}

	createError := login.Create()
	assert.Nil(t, createError)
}

func TestCreateLoginError(t *testing.T) {
	mockCQLClient := cassandra.NewMockClient()
	mockCQLClient.On("Exec", mock.AnythingOfType("string"), mock.AnythingOfType("[]interface {}")).Return(errors.New("CreateErrorMock"))

	login := &Login{
		Client:   mockCQLClient,
		Username: "createLoginTest",
		Name:     "Create Login Success Test",
		Password: "123mock321",
		Roles:    []string{"role1", "role2"},
	}

	createError := login.Create()
	assert.NotNil(t, createError)
}

func TestReadLoginSuccess(t *testing.T) {
	username := "readLoginTest"
	mockCQLClient := cassandra.NewMockClient()
	login := &Login{
		Client:   mockCQLClient,
		Username: username,
	}
	name := "Read Login Success Test"
	roles := []string{"role1"}

	mockCQLClient.On("QueryOne", mock.AnythingOfType("string"), mock.Anything, mock.AnythingOfType("[]interface {}")).Run(func(args mock.Arguments) {
		login.Username = username
		login.Name = name
		login.Roles = roles
	}).Return(nil)

	createError := login.Read()
	assert.Nil(t, createError)
	assert.Equal(t, login.Username, username)
	assert.Equal(t, login.Name, name)
	assert.Equal(t, login.Password, "")
	assert.Equal(t, login.Roles, roles)
}

func TestReadLoginError(t *testing.T) {
	mockCQLClient := cassandra.NewMockClient()
	mockCQLClient.On("QueryOne", mock.AnythingOfType("string"), mock.Anything, mock.AnythingOfType("[]interface {}")).Return(errors.New("ReadErrorMock"))

	login := &Login{
		Client: mockCQLClient,
	}

	readError := login.Read()
	assert.NotNil(t, readError)
}
