package model

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func BenchmarkCreateLoginSuccess(b *testing.B) {
	cqlClient := getPersistenceClient(b)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			login := &Login{
				Username: "createLoginTest",
				Name:     "Create Login Success Test",
				Password: "123mock321",
				Roles:    []string{"role1", "role2"},
			}

			createError := login.Create(cqlClient)
			assert.Nil(b, createError)
		}
	})
}

func BenchmarkmarkReadLoginSuccess(b *testing.B) {
	username := "makefile1"
	cqlClient := getPersistenceClient(b)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			login := &Login{
				Username: username,
			}

			createError := login.Read(cqlClient)
			assert.Nil(b, createError)
			assert.NotZero(b, login.Username)
			assert.NotZero(b, login.Name)
			assert.NotZero(b, login.Password)
			assert.NotZero(b, login.Roles)
		}
	})
}

func BenchmarkmarkSetSessionSuccess(b *testing.B) {
	cacheClient := getCacheClient(b)
	ttl := 1 * time.Hour
	id := "mockSession"
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			session := &Session{
				ID:  id,
				TTL: ttl,
			}
			setError := session.Set(cacheClient)
			assert.Nil(b, setError)
		}
	})
}

func BenchmarkmarkGetSessionSuccess(b *testing.B) {
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
	assert.Nil(b, err)
	cacheClient := getCacheClient(b)
	err = session.Set(cacheClient)
	assert.Nil(b, err)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			getError := session.Get(cacheClient)
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

func BenchmarkSerializePublicSessionSuccess(b *testing.B) {
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			session := &Session{
				ID:       "mockSession",
				Issuer:   "mockIssuer",
				Username: "mockUsername",
			}
			_, serializeError := session.Serialize()
			assert.Nil(b, serializeError)
		}
	})
}
