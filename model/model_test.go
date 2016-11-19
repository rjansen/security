package model

import (
	// "bytes"
	"errors"
	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/logger"
	cassandra "farm.e-pedion.com/repo/persistence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"
)

func TestUnitCreateLoginSuccess(t *testing.T) {
	mockCQLClient := cassandra.NewClientMock()
	mockCQLClient.On("Exec", mock.Anything, mock.Anything).Return(nil)

	login := &Login{
		Username: "createLoginTest",
		Name:     "Create Login Success Test",
		Password: "123mock321",
		Roles:    []string{"role1", "role2"},
	}

	createError := login.Create(mockCQLClient)
	assert.Nil(t, createError)
}

func TestUnitCreateLoginError(t *testing.T) {
	mockCQLClient := cassandra.NewClientMock()
	var login Login
	cases := []struct {
		username  string
		name      string
		password  string
		roles     []string
		mockError error
		out       string
	}{
		{"createLoginTest", "Create Login Test", "123mock321", []string{"role1", "role2"},
			errors.New("CreateErrorMock"), "CreateErrorMock"},
		{"", "Create Login Test", "123mock321", []string{"role1", "role2"}, nil, "Login.Username is empty"},
		{"createLoginTest", "", "123mock321", []string{"role1", "role2"}, nil, "Login.Name is empty"},
		{"createLoginTest", "Create Login Test", "", []string{"role1", "role2"}, nil, "Login.Password is empty"},
		{"createLoginTest", "Create Login Test", "123mock321", []string{}, nil, "Login.Roles is empty"},
	}
	for _, c := range cases {
		mockCQLClient.On("Exec", mock.AnythingOfType("string"), mock.AnythingOfType("[]interface {}")).Return(c.mockError)

		login.Username = c.username
		login.Name = c.name
		login.Password = c.password
		login.Roles = c.roles

		createError := login.Create(mockCQLClient)
		assert.NotNil(t, createError)
		assert.Contains(t, createError.Error(), c.out)
	}
}

func TestUnitReadLoginSuccess(t *testing.T) {
	username := "readLoginTest"
	mockCQLClient := cassandra.NewClientMock()
	login := &Login{
		Username: username,
	}
	name := "Read Login Success Test"
	roles := []string{"role1"}

	mockCQLClient.On("QueryOne", mock.AnythingOfType("string"), mock.Anything, mock.AnythingOfType("[]interface {}")).Run(func(args mock.Arguments) {
		login.Username = username
		login.Name = name
		login.Roles = roles
	}).Return(nil)

	createError := login.Read(mockCQLClient)
	assert.Nil(t, createError)
	assert.Equal(t, login.Username, username)
	assert.Equal(t, login.Name, name)
	assert.Equal(t, login.Password, "")
	assert.Equal(t, login.Roles, roles)
}

func TestUnitReadLoginError(t *testing.T) {
	mockCQLClient := cassandra.NewClientMock()
	var login Login
	cases := []struct {
		username  string
		mockError error
		out       string
	}{
		{"mock username", errors.New("ReadErrorMock"), "ReadErrorMock"},
		{"", nil, "Login.Username is empty"},
	}
	for _, c := range cases {
		mockCQLClient.On("QueryOne", mock.AnythingOfType("string"), mock.Anything, mock.AnythingOfType("[]interface {}")).Return(c.mockError)

		login.Username = c.username
		readError := login.Read(mockCQLClient)
		assert.NotNil(t, readError)
		//assert.Equal(t, c.mockError, readError)
		assert.Contains(t, readError.Error(), c.out)
	}
}

func TestUnitDeleteLoginSuccess(t *testing.T) {
	username := "deleteLoginTest"
	mockCQLClient := cassandra.NewClientMock()
	login := &Login{
		Username: username,
	}

	mockCQLClient.On("Exec", mock.AnythingOfType("string"), mock.AnythingOfType("[]interface {}")).Return(nil)

	deleteError := login.Delete(mockCQLClient)
	assert.Nil(t, deleteError)
}

func TestUnitDeleteLoginError(t *testing.T) {
	mockCQLClient := cassandra.NewClientMock()
	var login Login
	cases := []struct {
		username  string
		mockError error
		out       string
	}{
		{"mock username", errors.New("DeleteErrorMock"), "DeleteErrorMock"},
		{"", nil, "Login.Username is empty"},
	}
	for _, c := range cases {
		mockCQLClient.On("Exec", mock.AnythingOfType("string"), mock.AnythingOfType("[]interface {}")).Return(c.mockError)

		login.Username = c.username
		deleteError := login.Delete(mockCQLClient)
		assert.NotNil(t, deleteError)
		//assert.Equal(t, c.mockError, readError)
		assert.Contains(t, deleteError.Error(), c.out)
	}
}

func TestUnitSetSessionSuccess(t *testing.T) {
	logger.Setup(&logger.Configuration{Provider: logger.LOGRUS})
	mockCacheClient := cache.NewClientMock()
	ttl := 1 * time.Hour
	session := &Session{
		ID:  "mockSession",
		TTL: ttl,
	}
	mockCacheClient.On("Set",
		mock.AnythingOfType("string"),
		mock.AnythingOfType("int"),
		mock.Anything,
	).Return(nil)
	setError := session.Set(mockCacheClient)
	assert.Nil(t, setError)
}

func TestUnitGetSessionSuccess(t *testing.T) {
	sessionJSON := []byte(`
		{
			"iss": "mockIssuer",
			"id": "mockSession",
			"username": "mockUsername",
			"createdAt": "2016-07-10T09:15:38.000-03:00",
			"ttl": 3600000000,
			"expiresAt": "2016-07-10T10:15:38.000-03:00"
		}
	`)
	mockCacheClient := cache.NewClientMock()
	session := &Session{
		ID: "mockSession",
	}
	mockCacheClient.On("Get", mock.AnythingOfType("string")).Return(sessionJSON, nil)
	getError := session.Get(mockCacheClient)
	assert.Nil(t, getError)

	assert.Equal(t, session.Issuer, "mockIssuer")
	assert.Equal(t, session.ID, "mockSession")
	assert.Equal(t, session.Username, "mockUsername")
	assert.EqualValues(t, session.TTL, 3600000000)
	assert.NotZero(t, session.CreatedAt, "Session createdAt is zero")
	assert.NotZero(t, session.ExpiresAt, "Session expiresAt is zero")
}

func TestUnitSerializePublicSessionSuccess(t *testing.T) {
	session := &Session{
		ID:       "mockSession",
		Issuer:   "mockIssuer",
		Username: "mockUsername",
	}
	_, serializeError := session.Serialize()
	assert.Nil(t, serializeError)
}
