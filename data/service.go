package data

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/cassandra"
	"farm.e-pedion.com/repo/security/client/http"
	"farm.e-pedion.com/repo/security/identity"
	"farm.e-pedion.com/repo/security/util"
	"github.com/SermoDigital/jose/jws"
	"golang.org/x/crypto/bcrypt"
)

var (
	httpClient http.Client
)

//Authenticate loads the login representation and check his credentials
func Authenticate(username string, password string) (*PublicSession, error) {
	login := &Login{
		Username: username,
		Client:   cassandraClient,
	}
	if err := login.Read(); err != nil {
		log.Error("Authenticate.ReadLoginError",
			logger.String("Username", username),
			logger.Error(err),
		)
		return nil, err
	}
	if err := login.CheckCredentials(password); err != nil {
		log.Error("Authenticate.CheckCredentialsError",
			logger.String("Username", username),
			logger.Error(err),
		)
		return nil, err
	}
	publicSessionID, err := util.NewUUID()
	if err != nil {
		log.Error("Authenticate.NewPublicSessionIDError",
			logger.String("Username", username),
			logger.Error(err),
		)
		return nil, err
	}
	sessionID, err := util.NewUUID()
	if err != nil {
		log.Error("Authenticate.NewSessionIDError",
			logger.String("Username", username),
			logger.Error(err),
		)
		return nil, err
	}
	expires := time.Now().Add(day)
	publicSession := &PublicSession{
		Client:   cacheClient,
		Issuer:   "e-pedion.com",
		ID:       publicSessionID,
		Username: login.Username,
		PrivateSession: &identity.Session{
			Issuer:     "security.e-pedion.com",
			ID:         sessionID,
			Username:   login.Username,
			Roles:      login.Roles,
			CreateDate: time.Now(),
			TTL:        day,
			Expires:    expires,
		},
	}
	if proxyConfig.UseLoginCallback {
		if err := loginCallback(securityConfig.CookieName, proxyConfig.LoginCallbackURL, publicSession); err != nil {
			return nil, err
		}
	}
	if err := publicSession.Serialize(); err != nil {
		log.Error("data.Authenticate.JWTSerializeError",
			logger.String("Username", username),
			logger.Error(err),
		)
		return nil, err
	}
	if err := publicSession.Set(); err != nil {
		log.Error("Authenticate.SetSessionError",
			logger.String("Username", username),
			logger.Error(err),
		)
		return nil, err
	}
	log.Info("NewSession",
		logger.String("Username", username),
		logger.String("PublicID", publicSession.ID),
		logger.String("PrivateID", publicSession.PrivateSession.ID),
		logger.Error(err),
	)
	return publicSession, nil
}

func loginCallback(cookieName string, loginCallbackURL string, publicSession *PublicSession) error {
	if publicSession == nil || publicSession.PrivateSession == nil {
		return errors.New("InvalidRequiredParameter: Message='Public or private session is missed'")
	}
	if err := publicSession.PrivateSession.Serialize(); err != nil {
		return err
	}
	//client, err := util.GetTLSHttpClient()
	if httpClient == nil {
		httpClient = http.NewFastHTTPClient()
	}
	loginCallbackHeaders := map[string]interface{}{
		"Authorization": fmt.Sprintf("%v: %q", cookieName, publicSession.PrivateSession.Token),
		"Accept":        "application/json",
	}
	log.Debug("LoginCallbackRequest",
		logger.String("CallbackURL", loginCallbackURL),
		logger.Bytes(cookieName, publicSession.Token),
		logger.String("Username", publicSession.Username),
		logger.String("PrivateSession", publicSession.PrivateSession.String()),
	)
	response, err := httpClient.POST(loginCallbackURL, nil, loginCallbackHeaders)
	if err != nil {
		return err
	}

	if response.StatusCode() != 200 {
		return fmt.Errorf("LoginCallbackInvalidStatusCode[Message='Bad status code: %v']", response.StatusCode())
	}
	bodyBytes := response.Body()
	log.Debug("LoginCallbackResponse", logger.Int("ContentLength", response.ContentLength()))
	loginData := make(map[string]interface{})
	if err := json.Unmarshal(bodyBytes, &loginData); err != nil {
		return err
	}
	//delete(loginData, "username")
	log.Info("LoginCallbackData", logger.Struct("Data", loginData))
	publicSession.PrivateSession.Data = loginData
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
func ReadSession(token []byte) (*PublicSession, error) {
	jwt, err := jws.ParseJWT(token)
	if err != nil {
		return nil, err
	}
	if err := jwt.Validate(jwtKey, jwtCrypto); err != nil {
		return nil, err
	}
	publicSession := &PublicSession{
		Client:   cacheClient,
		ID:       jwt.Claims().Get("id").(string),
		Token:    []byte(token),
		Username: jwt.Claims().Get("username").(string),
	}
	if err := publicSession.Get(); err != nil {
		return nil, err
	}
	log.Debug("ReadSession", logger.Struct("PublicSession", publicSession))
	return publicSession, nil
}
