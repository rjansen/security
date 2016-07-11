package data

import (
	"bytes"
	"errors"
	"farm.e-pedion.com/repo/security/client/cassandra"
	"farm.e-pedion.com/repo/security/util"
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

func BenchmarkCreateLoginSuccess(b *testing.B) {
	mockCQLClient := cassandra.NewMockClient()
	mockCQLClient.On("Exec", mock.Anything, mock.Anything).Return(nil)

	for k := 0; k < b.N; k++ {
		login := &Login{
			Client:   mockCQLClient,
			Username: "createLoginTest",
			Name:     "Create Login Success Test",
			Password: "123mock321",
			Roles:    []string{"role1", "role2"},
		}

		createError := login.Create()
		assert.Nil(b, createError)
	}
}

func TestCreateLoginError(t *testing.T) {
	mockCQLClient := cassandra.NewMockClient()
	login := &Login{
		Client: mockCQLClient,
	}
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

		createError := login.Create()
		assert.NotNil(t, createError)
		assert.Contains(t, createError.Error(), c.out)
	}
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
	login := &Login{Client: mockCQLClient}
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
		readError := login.Read()
		assert.NotNil(t, readError)
		//assert.Equal(t, c.mockError, readError)
		assert.Contains(t, readError.Error(), c.out)
	}
}

func TestDeleteLoginSuccess(t *testing.T) {
	username := "deleteLoginTest"
	mockCQLClient := cassandra.NewMockClient()
	login := &Login{
		Client:   mockCQLClient,
		Username: username,
	}

	mockCQLClient.On("Exec", mock.AnythingOfType("string"), mock.AnythingOfType("[]interface {}")).Return(nil)

	deleteError := login.Delete()
	assert.Nil(t, deleteError)
}

func TestDeleteLoginError(t *testing.T) {
	mockCQLClient := cassandra.NewMockClient()
	login := &Login{Client: mockCQLClient}
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
		deleteError := login.Delete()
		assert.NotNil(t, deleteError)
		//assert.Equal(t, c.mockError, readError)
		assert.Contains(t, deleteError.Error(), c.out)
	}
}

func TestMarshalLoginSuccess(t *testing.T) {
	login := &Login{
		JSONObject: util.JSONObject{},
		Username:   "marshalLoginTest",
		Name:       "Marshal Login Test",
		Password:   "123mock321",
		Roles:      []string{"role1", "role2"},
	}

	loginBytes, marshallError := login.Marshal()
	assert.Nil(t, marshallError)
	assert.NotZero(t, len(loginBytes))
	loginJSON := string(loginBytes)
	assert.Contains(t, loginJSON, login.Username)
	assert.Contains(t, loginJSON, login.Name)
	assert.Contains(t, loginJSON, login.Password)
	assert.Contains(t, loginJSON, login.Roles[0])
	assert.Contains(t, loginJSON, login.Roles[1])
}

func TestUnmarshalLoginSuccess(t *testing.T) {
	loginJSON := []byte(`{
		"username": "darkside",
		"name": "Teste User Darkside",
		"password": "1234567890123456",
		"roles": ["adm", "user"]
		}`)
	loginJSONReader := bytes.NewReader(loginJSON)
	login := &Login{
		JSONObject: util.JSONObject{},
	}

	unmarshallError := login.Unmarshal(loginJSONReader)
	assert.Nil(t, unmarshallError)
	assert.Equal(t, login.Username, "darkside")
	assert.Equal(t, login.Name, "Teste User Darkside")
	assert.Equal(t, login.Password, "1234567890123456")
	assert.Equal(t, login.Roles, []string{"adm", "user"})
}

func TestUnmarshalBytesLoginSuccess(t *testing.T) {
	loginJSON := []byte(`{
		"username": "darkside",
		"name": "Teste User Darkside",
		"password": "1234567890123456",
		"roles": ["adm", "user"]
		}`)
	login := &Login{
		JSONObject: util.JSONObject{},
	}

	unmarshallError := login.UnmarshalBytes(loginJSON)
	assert.Nil(t, unmarshallError)
	assert.Equal(t, login.Username, "darkside")
	assert.Equal(t, login.Name, "Teste User Darkside")
	assert.Equal(t, login.Password, "1234567890123456")
	assert.Equal(t, login.Roles, []string{"adm", "user"})

}
