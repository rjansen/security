package data

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/security/database"
	"farm.e-pedion.com/repo/security/identity"
	"farm.e-pedion.com/repo/security/util"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"golang.org/x/crypto/bcrypt"
)

const (
	day = 24 * time.Hour
)

var (
	memoryCache    = make(map[string]*identity.Session)
	jwtKey         = []byte("321ewqdsa#@!")
	jwtCrypto      = crypto.SigningMethodHS512
	proxyConfig    = config.BindProxyConfiguration()
	securityConfig = config.BindSecurityConfiguration()
)

//Authenticate loads the login representation and check his credentials
func Authenticate(username string, password string) (*PublicSession, error) {
	login := &Login{Username: username}
	if err := login.Read(); err != nil {
		log.Printf("data.Authenticate.ReadLoginError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	if err := login.CheckCredentials(password); err != nil {
		log.Printf("data.Authenticate.CheckCredentialsError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	publicSessionID, err := util.NewUUID()
	if err != nil {
		log.Printf("data.Authenticate.NewPublicSessionIDError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	sessionID, err := util.NewUUID()
	if err != nil {
		log.Printf("data.Authenticate.NewSessionIDError: Username[%v] Error[%v]", username, err)
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
		log.Printf("data.Authenticate.JWTSerializeError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	if err := publicSession.Set(); err != nil {
		log.Printf("identity.Authenticate.SetSessionError: Username[%v] Error[%v]", username, err)
		return nil, err
	}
	log.Printf("data.Authenticate.NewSession: Username[%v] PublicID[%v] PrivateID[%v] Error[%v]", username, publicSession.ID, publicSession.PrivateSession.ID, err)
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
	log.Printf("data.LoginCallback.Authorization: CallbackURL=%v %v=%v Username=%v PrivateSession=%+v", loginCallbackURL, cookieName, string(publicSession.Token), publicSession.Username, publicSession.PrivateSession)
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
	log.Printf("LoginCallbackResponseBody: Body=%+v", string(bodyBytes))
	loginData := make(map[string]interface{})
	if err := json.Unmarshal(bodyBytes, &loginData); err != nil {
		return err
	}
	//delete(loginData, "username")
	log.Printf("LoginCallbackData: Data=%+v", loginData)
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

//Login is the data struct of the user identity
type Login struct {
	util.JSONObject
	database.SQLSupport
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

//CheckCredentials valoidatess if the the parameter is equal of the password field
func (l *Login) CheckCredentials(password string) error {
	return CheckHash(l.Password, password)
}

//Fetch fetchs the Row and sets the values into Login instance
func (l *Login) Fetch(fetchable database.Fetchable) error {
	return fetchable.Scan(&l.Username, &l.Name, &l.Password)
}

//FetchRoles fetchs all records in the provided role rows
func (l *Login) FetchRoles(roleRows *sql.Rows) error {
	var tempRoles []string
	for roleRows.Next() {
		var nextRole *string
		roleRows.Scan(&nextRole)
		tempRoles = append(tempRoles, *nextRole)
	}
	l.Roles = tempRoles
	return nil
}

//Read gets the entity representation from the database.
func (l *Login) Read() error {
	if strings.TrimSpace(l.Username) == "" {
		return errors.New("data.Login.ReadError: Message='Login.Username is empty'")
	}
	err := l.QueryOne("select username, name, password from login where username = ?", l.Fetch, l.Username)
	if err != nil {
		return err
	}
	err = l.Query("select rolename from login_role where username = ?", l.FetchRoles, l.Username)
	if err != nil {
		return err
	}
	return nil
}

//Persist persists the entity representation in the database.
func (l *Login) Persist() error {
	if strings.TrimSpace(l.Username) == "" {
		return errors.New("data.Login.PersistError: Message='Login.Username is empty'")
	}
	if strings.TrimSpace(l.Name) == "" {
		return errors.New("data.Login.PersistError: Message='Login.Name is empty'")
	}
	if strings.TrimSpace(l.Password) == "" {
		return errors.New("data.Login.PersistError: Message='Login.Password is empty'")
	}
	hashedPassword, err := Hash(l.Password)
	if err != nil {
		return err
	}
	l.Password = string(hashedPassword)

	err = l.Insert("insert into login (username, name, password) values (?, ?, ?)", l.Username, l.Name, l.Password)
	if err != nil {
		return err
	}
	insertRole := "insert into login_role (username, rolename) values (?, ?)"
	for _, role := range l.Roles {
		insertRoleErr := l.Insert(insertRole, l.Username, role)
		if insertRoleErr != nil {
			log.Printf("data.Login.PersistError.InsertRoleEx: Message='%v'", insertRoleErr.Error())
			return insertRoleErr
		}
	}
	return nil
}

//Remove removes the entity representation from the database
func (l *Login) Remove() error {
	if strings.TrimSpace(l.Username) == "" {
		return errors.New("data.Login.RemoveError: Message='Login.Username is empty'")
	}
	err := l.Delete("delete from login_role where username = ?", l.Username)
	if err != nil {
		return err
	}
	return l.Delete("delete from login where username = ?", l.Username)
}

//Marshal to a JSON representation
func (l *Login) Marshal() ([]byte, error) {
	return l.JSONObject.Marshal(&l)
}

//Unmarshal from a JSON representation
func (l *Login) Unmarshal(reader io.Reader) error {
	return l.JSONObject.Unmarshal(&l, reader)
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
	log.Printf("data.ReadSession: PublicSession[%+v]", publicSession.ID)
	if err := publicSession.Get(); err != nil {
		return nil, err
	}
	return publicSession, nil
}

//PublicSession represents a public ticket to call the security system
type PublicSession struct {
	util.JSONObject
	Issuer         string            `json:"iss"`
	ID             string            `json:"id"`
	Username       string            `json:"username"`
	PrivateSession *identity.Session `json:"privateSession"`
	Token          []byte            `json:"-"`
}

func (s *PublicSession) String() string {
	return fmt.Sprintf("PublicSession[ID=%v Username=%v Issuer=%v PrivateSession=%v]", s.ID, s.Username, s.Issuer, s.PrivateSession)
}

//Set sets the session to cache
func (s *PublicSession) Set() error {
	log.Printf("data.StoreSession: Session=%+v", s.PrivateSession)
	memoryCache[s.ID] = s.PrivateSession
	if memoryCache[s.ID] == nil {
		return fmt.Errorf("data.SetSessionError: Message='ImpossibleToCacheSession: ID=%v'", s.ID)
	}
	return nil
}

//Get gets the session from cache
func (s *PublicSession) Get() error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("data.PublicSession.Get: Message='PublicSession.ID is empty'")
	}
	log.Printf("data.PublicSession.LoadSessionFromCache: ID=%v", s.ID)
	privateSession := memoryCache[s.ID]
	if privateSession == nil {
		return fmt.Errorf("data.SessionInvalid: Message='SessionInvalid: Cache=%v ID=%v'", memoryCache, s.ID)
	}
	s.PrivateSession = privateSession
	return nil
}

//Refresh refreshs the session data
func (s *PublicSession) Refresh() error {
	return nil
}

//Marshal to a JSON representation
func (s *PublicSession) Marshal() ([]byte, error) {
	return s.JSONObject.Marshal(&s)
}

//Unmarshal from a JSON representation
func (s *PublicSession) Unmarshal(reader io.Reader) error {
	return s.JSONObject.Unmarshal(&s, reader)
}

//Serialize writes a JWT representation of this Session in the Token field
func (s *PublicSession) Serialize() error {
	claims := jws.Claims{
		"id":       s.ID,
		"iss":      s.Issuer,
		"username": s.Username,
	}
	// if s.PrivateSession != nil {
	// 	claims.Set("privateSession", s.Data)
	// }
	jwt := jws.NewJWT(claims, jwtCrypto)
	token, err := jwt.Serialize(jwtKey)
	if err != nil {
		return err
	}
	s.Token = token
	return nil
}
