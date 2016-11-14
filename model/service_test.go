package model

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/persistence"
	"farm.e-pedion.com/repo/security/client/http"
	"farm.e-pedion.com/repo/security/identity"
	"testing"
)

type fetchableMock struct {
	mock.Mock
}

func (m *fetchableMock) Scan(dest ...interface{}) error {
	args := m.Called(dest)
	return args.Error(0)
}

func TestUnitAuthenticate(t *testing.T) {
	proxyConfig = &identity.ProxyConfig{
		UseLoginCallback: true,
		LoginCallbackURL: "http://mock/login/callback",
	}
	securityConfig = &identity.SecurityConfig{
		CookieName: "mockSessionCookie",
	}
	body := []byte(`{}`)
	httpResponseMock := http.NewResponseMock()
	httpResponseMock.On("StatusCode").Return(200)
	httpResponseMock.On("ContentLength").Return(len(body))
	httpResponseMock.On("Body").Return(body)
	httpClientMock := http.NewClientMock()
	httpClientMock.On("POST", mock.Anything, mock.Anything, mock.Anything).Return(httpResponseMock, nil)
	httpClient = httpClientMock
	persistenceClient := persistence.NewClientMock()
	persistenceClient.On("Closed").Return(false)
	persistenceClient.On("Close").Return(nil)
	fetchable := new(fetchableMock)
	fetchable.On("Scan", mock.Anything).Return(nil).Run(
		func(args mock.Arguments) {
			a := args.Get(0)
			assert.NotNil(t, a)
			if a != nil {
				dest := a.([]interface{})
				assert.Len(t, dest, 4)
				username := dest[0].(*string)
				*username = "MockUsername"
				name := dest[1].(*string)
				*name = "Mock Name"
				password := dest[2].(*string)
				*password = "$2a$10$hZ7fh4t49n3TZo0buYgdeeeskTQ0t.NMFUIK/WVFhqPAQUQnChSSi"
				roles := dest[3].(*[]string)
				*roles = []string{"mockrole1", "mockrole2", "mockrole3"}
			}
		},
	)

	persistenceClient.On("QueryOne", mock.Anything, mock.Anything, mock.Anything).Return(nil).Run(
		func(args mock.Arguments) {
			fetchArg := args.Get(1)
			if fetchArg != nil {
				fetchFunc := fetchArg.(func(persistence.Fetchable) error)
				fetchFunc(fetchable)
			}
		},
	)
	persistencePool := persistence.NewClientPoolMock()
	persistencePool.On("Get").Return(persistenceClient, nil)

	cacheClient := cache.NewClientMock()
	cacheClient.On("Close").Return(nil)
	cacheClient.On("Set", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	cachePool := cache.NewClientPoolMock()
	cachePool.On("Get").Return(cacheClient, nil)

	assert.Nil(t, persistence.Setup(persistencePool))
	assert.Nil(t, cache.Setup(cachePool))

	session, err := Authenticate("mockUser", "1234567890123456")
	assert.Nil(t, err)
	assert.NotNil(t, session)

	cacheClient.On("Get", mock.Anything).Return(
		[]byte(`{"id": "mockID", "username": "MockSession", "iss": "mockIss"}`),
		nil,
	)
	token, err := session.Serialize()
	assert.Nil(t, err)
	assert.NotNil(t, token)

	readSession, err := ReadSession(token)
	assert.Nil(t, err)
	assert.NotNil(t, readSession)
	assert.Equal(t, "mockID", readSession.ID)
	assert.Equal(t, "MockSession", readSession.Username)
	assert.Equal(t, "mockIss", readSession.Issuer)
}
