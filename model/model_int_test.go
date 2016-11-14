package model

import (
	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/cache/memcached"
	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/persistence"
	"farm.e-pedion.com/repo/persistence/cassandra"
	"github.com/matryer/resync"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

var (
	intSetup resync.Once
)

func init() {
	os.Args = append(os.Args, "-ecf", "../test/etc/security/benchmark.yaml")
	logger.Info("model_test.init")
}

func setup() {
	intSetup.Do(func() {
		var cassandraCfg *cassandra.Configuration
		var err error
		if err = config.UnmarshalKey("cassandra", &cassandraCfg); err != nil {
			panic(err)
		}
		if err := cassandra.Setup(cassandraCfg); err != nil {
			panic(err)
		}
		var memcachedCfg *memcached.Configuration
		if err = config.UnmarshalKey("memcached", &memcachedCfg); err != nil {
			panic(err)
		}
		if err := memcached.Setup(memcachedCfg); err != nil {
			panic(err)
		}
	})
}

func getPersistenceClient(t assert.TestingT) persistence.Client {
	setup()
	pool, err := persistence.GetPool()
	assert.Nil(t, err)
	assert.NotNil(t, pool)

	client, err := pool.Get()
	assert.Nil(t, err)
	assert.NotNil(t, client)
	return client
}

func getCacheClient(t assert.TestingT) cache.Client {
	setup()
	pool, err := cache.GetPool()
	assert.Nil(t, err)
	assert.NotNil(t, pool)

	client, err := pool.Get()
	assert.Nil(t, err)
	assert.NotNil(t, client)
	return client
}

func TestIntCreateLoginSuccess(t *testing.T) {
	cqlClient := getPersistenceClient(t)

	login := &Login{
		Username: "createLoginTest",
		Name:     "Create Login Success Test",
		Password: "123mock321",
		Roles:    []string{"role1", "role2"},
	}

	createError := login.Create(cqlClient)
	assert.Nil(t, createError)
}

func TestIntReadLoginSuccess(t *testing.T) {
	username := "makefile1"
	cqlClient := getPersistenceClient(t)
	login := &Login{
		Username: username,
	}

	createError := login.Read(cqlClient)
	assert.Nil(t, createError)
	assert.NotZero(t, login.Username)
	assert.NotZero(t, login.Name)
	assert.NotZero(t, login.Password)
	assert.NotZero(t, login.Roles)
}

func TestIntSetSessionSuccess(t *testing.T) {
	cacheClient := getCacheClient(t)
	ttl := 1 * time.Hour
	session := &Session{
		ID:  "mockSession",
		TTL: ttl,
	}
	setError := session.Set(cacheClient)
	assert.Nil(t, setError)
}

func TestIntGetSessionSuccess(t *testing.T) {
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
	var session Session
	err := session.UnmarshalBytes(sessionJSON)
	assert.Nil(t, err)
	cacheClient := getCacheClient(t)
	err = session.Set(cacheClient)
	assert.Nil(t, err)

	getError := session.Get(cacheClient)
	assert.Nil(t, getError)

	assert.Equal(t, session.Issuer, "mockIssuer")
	assert.Equal(t, session.ID, "mockSession")
	assert.Equal(t, session.Username, "mockUsername")
	assert.EqualValues(t, session.TTL, 3600000000)
	assert.NotZero(t, session.CreatedAt, "Session createdAt is zero")
	assert.NotZero(t, session.ExpiresAt, "Session expiresAt is zero")
}

func TestIntSerializePublicSessionSuccess(t *testing.T) {
	session := &Session{
		ID:       "mockSession",
		Issuer:   "mockIssuer",
		Username: "mockUsername",
	}
	_, serializeError := session.Serialize()
	assert.Nil(t, serializeError)
}
