package data

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"farm.e-pedion.com/repo/security/identity"
	"farm.e-pedion.com/repo/security/util"
	"github.com/SermoDigital/jose/jws"
	"golang.org/x/crypto/bcrypt"
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
	log.Infof("Authenticate.NewSession: Username[%v] PublicID[%v] PrivateID[%v] Error[%v]", username, publicSession.ID, publicSession.PrivateSession.ID, err)
	return publicSession, nil
}

func loginCallback(cookieName string, loginCallbackURL string, publicSession *PublicSession) error {
	if publicSession == nil || publicSession.PrivateSession == nil {
		return errors.New("InvalidRequiredParameter: Message='Public or private session is missed'")
	}
	if err := publicSession.PrivateSession.Serialize(); err != nil {
		return err
	}
	client, err := util.GetTLSHttpClient()
	if err != nil {
		return err
	}
	request, err := http.NewRequest("POST", loginCallbackURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", fmt.Sprintf("%v: %v", cookieName, string(publicSession.PrivateSession.Token)))
	log.Debugf("LoginCallback.Authorization: CallbackURL=%v %v=%v Username=%v PrivateSession=%+v", loginCallbackURL, cookieName, string(publicSession.Token), publicSession.Username, publicSession.PrivateSession)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("LoginCallbackInvalidStatusCode: Message='Bad status code: %v'", response.StatusCode)
	}
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	log.Debugf("LoginCallbackResponseBody: Body=%+v", string(bodyBytes))
	loginData := make(map[string]interface{})
	if err := json.Unmarshal(bodyBytes, &loginData); err != nil {
		return err
	}
	//delete(loginData, "username")
	log.Infof("LoginCallbackData: Data=%+v", loginData)
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
func ReadSession(token string) (*PublicSession, error) {
	jwt, err := jws.ParseJWT([]byte(token))
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
	log.Debugf("ReadSession: PublicSession[%+v]", publicSession.ID)
	if err := publicSession.Get(); err != nil {
		return nil, err
	}
	return publicSession, nil
}
