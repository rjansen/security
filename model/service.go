package model

import (
	"errors"
	"fmt"
	"time"

	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/persistence"
	"farm.e-pedion.com/repo/security/client/http/fast"
	"farm.e-pedion.com/repo/security/identity"
	"farm.e-pedion.com/repo/security/util"
	"github.com/SermoDigital/jose/jws"
	"golang.org/x/crypto/bcrypt"
)

//Authenticate loads the login representation and check his credentials
func Authenticate(username string, password string) (*Session, error) {
	login := &Login{
		Username: username,
	}
	if err := persistence.Execute(login.Read); err != nil {
		logger.Error("Authenticate.ReadLoginError",
			logger.String("Username", username),
			logger.Err(err),
		)
		return nil, err
	}
	logger.Info("model.Authenticate", logger.String("User", login.String()))
	if err := login.CheckCredentials(password); err != nil {
		logger.Error("Authenticate.CheckCredentialsError",
			logger.String("Username", username),
			logger.Err(err),
		)
		return nil, err
	}
	sessionID, err := util.NewUUID()
	if err != nil {
		logger.Error("Authenticate.NewPublicSessionIDError",
			logger.String("Username", username),
			logger.Err(err),
		)
		return nil, err
	}
	expires := time.Now().Add(day)
	session := &Session{
		ID:        sessionID,
		Issuer:    "e-pedion.com",
		Username:  login.Username,
		CreatedAt: time.Now(),
		TTL:       day,
		ExpiresAt: expires,
	}
	if proxyConfig.UseLoginCallback {
		if err := loginCallback(securityConfig.CookieName, proxyConfig.LoginCallbackURL, session); err != nil {
			return nil, err
		}
	}
	if err := cache.Execute(session.Set); err != nil {
		logger.Error("Authenticate.SetSessionError",
			logger.String("Username", username),
			logger.Err(err),
		)
		return nil, err
	}
	logger.Info("NewSession",
		logger.String("Username", session.Username),
		logger.String("ID", session.ID),
		logger.Int("data.len", len(session.Data)),
		logger.Err(err),
	)
	return session, nil
}

func loginCallback(cookieName string, loginCallbackURL string, session *Session) error {
	if session == nil {
		return errors.New("InvalidRequiredParameter: Message='Public or private session is missed'")
	}
	privateSessionID, err := util.NewUUID()
	if err != nil {
		logger.Error("LoginCallback.NewSessionIDError",
			logger.String("Username", session.Username),
			logger.Err(err),
		)
		return err
	}
	//client, err := util.GetTLSHttpClient()
	if httpClient == nil {
		httpClient = fast.NewFastHTTPClient()
	}
	privateSession := identity.Session{
		Id:       privateSessionID,
		Username: session.Username,
		Roles:    []string{"e-user"},
		Issuer:   "e-pedion.com/security",
	}
	token, err := identity.Serialize(privateSession)
	if err != nil {
		return err
	}
	loginCallbackHeaders := map[string]string{
		"Authorization": fmt.Sprintf("%v: %q", cookieName, token),
		"Accept":        "application/json",
	}
	logger.Debug("LoginCallbackRequest",
		logger.String("CallbackURL", loginCallbackURL),
		logger.Bytes(cookieName, token),
		logger.String("Username", session.Username),
	)
	response, err := httpClient.POST(loginCallbackURL, nil, loginCallbackHeaders)
	if err != nil {
		return err
	}

	if response.StatusCode() != 200 {
		return fmt.Errorf("LoginCallbackInvalidStatusCode[Message='Bad status code: %v']", response.StatusCode())
	}
	session.Data = response.Body()
	logger.Debug("LoginCallbackResponse",
		logger.Int("data.len", len(session.Data)),
		logger.Int("ContentLength", response.ContentLength()),
	)
	return nil
}

//Hash hashs the plain text with bcrypt and default cost
func Hash(plain string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
}

//CheckHash compares if the the hashed is equal to the hashed plain value
func CheckHash(hashed string, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
}

//ReadSession loads session from cache
func ReadSession(token []byte) (*Session, error) {
	jwt, err := jws.ParseJWT(token)
	if err != nil {
		return nil, err
	}
	if err := jwt.Validate(jwtKey, jwtCrypto); err != nil {
		return nil, err
	}
	session := &Session{
		ID:       jwt.Claims().Get("id").(string),
		Username: jwt.Claims().Get("username").(string),
	}
	if err := cache.Execute(session.Get); err != nil {
		return nil, err
	}
	logger.Debug("ReadSession", logger.Struct("Session", session))
	return session, nil
}
