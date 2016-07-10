package data

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
	login := &Login{Username: username}
	if err := login.Read(); err != nil {
		log.Errorf("Authenticate.ReadLoginError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	if err := login.CheckCredentials(password); err != nil {
		log.Errorf("Authenticate.CheckCredentialsError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	publicSessionID, err := util.NewUUID()
	if err != nil {
		log.Errorf("Authenticate.NewPublicSessionIDError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	sessionID, err := util.NewUUID()
	if err != nil {
		log.Errorf("Authenticate.NewSessionIDError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	expires := time.Now().Add(day)
	publicSession := &PublicSession{
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
		log.Errorf("data.Authenticate.JWTSerializeError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	if err := publicSession.Set(); err != nil {
		log.Errorf("Authenticate.SetSessionError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	log.Infof("NewSession[Username=%v PublicID=%v PrivateID=%v Error=%v]", username, publicSession.ID, publicSession.PrivateSession.ID, err)
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
	log.Debugf("LoginCallbackRequest[CallbackURL=%v %v=%q Username=%v PrivateSession=%+v]", loginCallbackURL, cookieName, publicSession.Token, publicSession.Username, publicSession.PrivateSession)
	response, err := httpClient.POST(loginCallbackURL, nil, loginCallbackHeaders)
	if err != nil {
		return err
	}

	if response.StatusCode() != 200 {
		return fmt.Errorf("LoginCallbackInvalidStatusCode[Message='Bad status code: %v']", response.StatusCode())
	}
	bodyBytes := response.Body()
	log.Debugf("LoginCallbackResponse[ContentLength=%d]", response.ContentLength())
	loginData := make(map[string]interface{})
	if err := json.Unmarshal(bodyBytes, &loginData); err != nil {
		return err
	}
	//delete(loginData, "username")
	log.Infof("LoginCallbackData[Data=%+v]", loginData)
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
		ID:       jwt.Claims().Get("id").(string),
		Token:    []byte(token),
		Username: jwt.Claims().Get("username").(string),
	}
	if err := publicSession.Get(); err != nil {
		return nil, err
	}
	log.Debugf("ReadSession[PublicSession=%+v]", publicSession)
	return publicSession, nil
}
