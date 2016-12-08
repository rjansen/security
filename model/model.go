package model

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/context/media/json"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/persistence"
	"farm.e-pedion.com/repo/persistence/cassandra"
	"farm.e-pedion.com/repo/security/client/http"
	"farm.e-pedion.com/repo/security/identity"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

const (
	day = 24 * time.Hour
)

var (
	proxyConfig    *identity.ProxyConfig
	securityConfig *identity.SecurityConfig
	httpClient     http.Client
	//memoryCache    = make(map[string]*identity.Session)

	jwtKey    = []byte("321ewqdsa#@!")
	jwtCrypto = crypto.SigningMethodHS512
	//NotFoundErr is the error that returns when a read one dont match any record
	NotFoundErr = cassandra.NotFoundErr
)

//Setup configures the package
func Setup(cfg *identity.Configuration) error {
	logger.Info("data.SetupStart")
	proxyConfig = &cfg.Proxy
	securityConfig = &cfg.Security
	logger.Info("data.SetupEnd")
	return nil
}

//Authenticator is the data struct of the security authenticato configuration
type Authenticator struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Title    string `json:"label"`
	Keywords string `json:"keywords"`
	Author   string `json:"author"`
}

//LoginPageData holds login page beahavior and appearance
type LoginPageData struct {
	Authenticator `json:"authenticator"`
	//Error, Warning, Info
	MessageType   string        `json:"messageType"`
	Message       string        `json:"message"`
	LoginUserData LoginUserData `json:"userData"`
}

//LoginUserData holds login form behavior and appearance
type LoginUserData struct {
	ProductLabel      string `json:"productLabel"`
	RemmenberUser     bool   `json:"remmenberUser"`
	Username          string `json:"username"`
	ImageURL          string `json:"imageURL"`
	FormURI           string `json:"formURI"`
	FormUsernameField string `json:"formUsernameField"`
	FormPasswordField string `json:"formPasswordField"`
}

//Login is the data struct of the user identity
type Login struct {
	Username string
	Name     string
	Password string
	Roles    []string
}

func (l Login) String() string {
	return fmt.Sprintf("data.Login Username=%s Name=%s Roles=%v", l.Username, l.Name, l.Roles)
}

//CheckCredentials valoidatess if the the parameter is equal of the password field
func (l Login) CheckCredentials(password string) error {
	return CheckHash(l.Password, password)
}

//Fetch fetchs the Row and sets the values into Login instance
func (l *Login) Fetch(fetchable persistence.Fetchable) error {
	return fetchable.Scan(&l.Username, &l.Name, &l.Password, &l.Roles)
}

//Read gets the entity representation from the database.
func (l *Login) Read(client persistence.Client) error {
	if strings.TrimSpace(l.Username) == "" {
		return errors.New("ReadError[Message='Login.Username is empty']")
	}
	return client.QueryOne("select username, name, password, roles from login where username = ? limit 1", l.Fetch, l.Username)
}

//Create adds a new login record to the database.
func (l *Login) Create(client persistence.Client) error {
	if strings.TrimSpace(l.Username) == "" {
		return errors.New("PersistError: Message='Login.Username is empty'")
	}
	if strings.TrimSpace(l.Name) == "" {
		return errors.New("PersistError: Message='Login.Name is empty'")
	}
	if strings.TrimSpace(l.Password) == "" {
		return errors.New("PersistError: Message='Login.Password is empty'")
	}
	if len(l.Roles) <= 0 {
		return errors.New("PersistError: Message='Login.Roles is empty'")
	}
	hashedPassword, err := Hash(l.Password)
	if err != nil {
		return err
	}
	l.Password = string(hashedPassword)
	return client.Exec("insert into login (username, name, password, roles) values (?, ?, ?, ?)", l.Username, l.Name, l.Password, l.Roles)
}

//Delete removes the login record from the database
func (l *Login) Delete(client persistence.Client) error {
	if strings.TrimSpace(l.Username) == "" {
		return errors.New("RemoveError: Message='Login.Username is empty'")
	}
	return client.Exec("delete from login where username = ?", l.Username)
}

//Session represents a public ticket to call the security system
type Session struct {
	ID        string        `json:"id"`
	Username  string        `json:"username"`
	Issuer    string        `json:"iss"`
	CreatedAt time.Time     `json:"createdAt"`
	TTL       time.Duration `json:"ttl"`
	ExpiresAt time.Time     `json:"expiresAt"`
	Data      []byte        `json:"data"`
}

func (s Session) String() string {
	return fmt.Sprintf("model.Session ID=%v Username=%s Issuer=%v ExpiresAt=%s]", s.ID, s.Username, s.Issuer, s.ExpiresAt)
}

//Set sets the session to cache
func (s *Session) Set(client cache.Client) error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("data.Session.SetErr msg='The Session.ID field cannot be blank'")
	}
	ttl := int(s.TTL / time.Second)
	logger.Debug("StoringSession",
		logger.String("ID", s.ID),
		logger.String("Username", s.Username),
		logger.Duration("TTL", s.TTL),
		logger.Time("Expires", s.ExpiresAt),
	)
	sessionBytes, err := json.MarshalBytes(s)
	if err != nil {
		return fmt.Errorf("MarshalSessionError: Message='ImpossibleToMarshalSession: ID=%v Cause=%v'", s.ID, err)
	}
	err = client.Set(s.ID, ttl, sessionBytes)
	if err != nil {
		return fmt.Errorf("SetSessionError: Message='ImpossibleToCacheSession: ID=%v Cause=%v'", s.ID, err)
	}
	logger.Info("SessionStored",
		logger.String("ID", s.ID),
		logger.Int("TTL", ttl),
		logger.Int("ValueLen", len(sessionBytes)),
	)
	return nil
}

//Get gets the session from cache
func (s *Session) Get(client cache.Client) error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("data.Session.GetErr Message='PublicSession.ID is empty'")
	}
	sessionBytes, err := client.Get(s.ID)
	if err != nil {
		return fmt.Errorf("data.GetSessionError: Message='ImpossibleToGetCachedSession: ID=%v Cause=%v'", s.ID, err.Error())
	}
	logger.Debug("SessionLoadedFromCache",
		logger.String("ID", s.ID),
		logger.Int("ValueLen", len(sessionBytes)),
	)
	err = s.UnmarshalBytes(sessionBytes)
	if err != nil {
		return fmt.Errorf("data.UnmarshalSessionError: Message='ImpossibleToUnmarshalSession: ID=%v Cause=%v'", s.ID, err.Error())
	}
	return nil
}

//Del removes the session from cache
func (s *Session) Del(client cache.Client) error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("data.Session.DelErr Message='Session.ID is empty'")
	}
	if err := client.Delete(s.ID); err != nil {
		return fmt.Errorf("data.DelSessionError: Message='ImpossibleToDelCachedSession: ID=%s Cause=%s'", s.ID, err.Error())
	}
	logger.Info("SessionDeletedFromCache",
		logger.String("ID", s.ID),
	)
	return nil
}

//Marshal writes a json representation of the struct instance
func (s *Session) Marshal(w io.Writer) error {
	return json.Marshal(w, &s)
}

//Unmarshal reads a json representation into the struct instance
func (s *Session) Unmarshal(r io.Reader) error {
	return json.Unmarshal(r, &s)
}

//MarshalBytes writes a json representation of the struct instance
func (s *Session) MarshalBytes() ([]byte, error) {
	return json.MarshalBytes(&s)
}

//UnmarshalBytes reads a json representation into the struct instance
func (s *Session) UnmarshalBytes(data []byte) error {
	return json.UnmarshalBytes(data, &s)

}

//Serialize writes a JWT representation of this Session in the Token field
func (s *Session) Serialize() ([]byte, error) {
	claims := jws.Claims{
		"id":       s.ID,
		"iss":      s.Issuer,
		"username": s.Username,
	}
	jwt := jws.NewJWT(claims, jwtCrypto)
	token, err := jwt.Serialize(jwtKey)
	return token, err
}
