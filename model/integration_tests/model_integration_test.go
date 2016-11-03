package integration_test

import (
	// "bytes"
	// "errors"
	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/db/cassandra"
	"farm.e-pedion.com/repo/security/model"
	"time"
	//"farm.e-pedion.com/repo/security/util"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func init() {
	os.Args = append(os.Args, "-ecf", "../test/etc/security/benchmark.yaml")
	logger.Info("model_integration_test.init")
	if err := cassandra.Setup(); err != nil {
		panic(err)
	}
	if err := cache.Setup(); err != nil {
		panic(err)
	}
}

func TestIntegrationCreateLoginSuccess(t *testing.T) {
	cqlClient := cassandra.NewClient()

	login := &model.Login{
		Client:   cqlClient,
		Username: "createLoginTest",
		Name:     "Create Login Success Test",
		Password: "123mock321",
		Roles:    []string{"role1", "role2"},
	}

	createError := login.Create()
	assert.Nil(t, createError)
}

func BenchmarkCreateLoginSuccess(b *testing.B) {
	cqlClient := cassandra.NewClient()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			login := &model.Login{
				Client:   cqlClient,
				Username: "createLoginTest",
				Name:     "Create Login Success Test",
				Password: "123mock321",
				Roles:    []string{"role1", "role2"},
			}

			createError := login.Create()
			assert.Nil(b, createError)
		}
	})
}

func TestIntegrationReadLoginSuccess(t *testing.T) {
	username := "makefile1"
	cqlClient := cassandra.NewClient()
	login := &model.Login{
		Client:   cqlClient,
		Username: username,
	}

	createError := login.Read()
	assert.Nil(t, createError)
	assert.NotZero(t, login.Username)
	assert.NotZero(t, login.Name)
	assert.NotZero(t, login.Password)
	assert.NotZero(t, login.Roles)
}

func BenchmarkReadLoginSuccess(b *testing.B) {
	username := "makefile1"
	cqlClient := cassandra.NewClient()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			login := &model.Login{
				Client:   cqlClient,
				Username: username,
			}

			createError := login.Read()
			assert.Nil(b, createError)
			assert.NotZero(b, login.Username)
			assert.NotZero(b, login.Name)
			assert.NotZero(b, login.Password)
			assert.NotZero(b, login.Roles)
		}
	})
}

func TestIntegrationSetSessionSuccess(t *testing.T) {
	cacheClient := cache.NewClient()
	ttl := 1 * time.Hour
	session := &model.Session{
		Client: cacheClient,
		ID:     "mockSession",
		TTL:    ttl,
	}
	setError := session.Set()
	assert.Nil(t, setError)
}

func BenchmarkSetSessionSuccess(b *testing.B) {
	cacheClient := cache.NewClient()
	ttl := 1 * time.Hour
	id := "mockSession"
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			session := &model.Session{
				Client: cacheClient,
				ID:     id,
				TTL:    ttl,
			}
			setError := session.Set()
			assert.Nil(b, setError)
		}
	})
}

func TestIntegrationGetSessionSuccess(t *testing.T) {
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
	var session model.Session
	err := session.UnmarshalBytes(sessionJSON)
	assert.Nil(t, err)
	session.Client = cache.NewClient()
	assert.NotNil(t, session.Client)
	err = session.Set()
	assert.Nil(t, err)

	getError := session.Get()
	assert.Nil(t, getError)

	assert.Equal(t, session.Issuer, "mockIssuer")
	assert.Equal(t, session.ID, "mockSession")
	assert.Equal(t, session.Username, "mockUsername")
	assert.EqualValues(t, session.TTL, 3600000000)
	assert.NotZero(t, session.CreatedAt, "Session createdAt is zero")
	assert.NotZero(t, session.ExpiresAt, "Session expiresAt is zero")
}

func BenchmarkGetSessionSuccess(b *testing.B) {
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
	var session model.Session
	err := session.UnmarshalBytes(sessionJSON)
	assert.Nil(b, err)
	session.Client = cache.NewClient()
	assert.NotNil(b, session.Client)
	err = session.Set()
	assert.Nil(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			getError := session.Get()
			assert.Nil(b, getError)

			assert.Equal(b, session.Issuer, "mockIssuer")
			assert.Equal(b, session.ID, "mockSession")
			assert.Equal(b, session.Username, "mockUsername")
			assert.EqualValues(b, session.TTL, 3600000000)
			assert.NotZero(b, session.CreatedAt, "Session createdAt is zero")
			assert.NotZero(b, session.ExpiresAt, "Session expiresAt is zero")
		}
	})
}

func TestIntegrationSerializePublicSessionSuccess(t *testing.T) {
	session := &model.Session{
		ID:       "mockSession",
		Issuer:   "mockIssuer",
		Username: "mockUsername",
	}
	_, serializeError := session.Serialize()
	assert.Nil(t, serializeError)
}

func BenchmarkSerializePublicSessionSuccess(b *testing.B) {
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			session := &model.Session{
				ID:       "mockSession",
				Issuer:   "mockIssuer",
				Username: "mockUsername",
			}
			_, serializeError := session.Serialize()
			assert.Nil(b, serializeError)
		}
	})
}
