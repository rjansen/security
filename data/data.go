package data

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/cassandra"
	localConfig "farm.e-pedion.com/repo/security/config"
	"farm.e-pedion.com/repo/security/identity"
	"farm.e-pedion.com/repo/security/util"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

const (
	day = 24 * time.Hour
)

var (
	proxyConfig     *localConfig.ProxyConfig
	securityConfig  *localConfig.SecurityConfig
	cacheClient     cache.Client
	cassandraClient cassandra.Client
	//memoryCache    = make(map[string]*identity.Session)

	jwtKey    = []byte("321ewqdsa#@!")
	jwtCrypto = crypto.SigningMethodHS512
	//NotFoundErr is the error that returns when a read one dont match any record
	NotFoundErr = cassandra.NotFoundErr
)

func Setup() error {
	logger.Info("data.SetupStart")
	if err := config.UnmarshalKey("proxy", &proxyConfig); err != nil {
		logger.Info("data.GetProxyConfigErr", logger.Err(err))
		return err
	}
	if err := config.UnmarshalKey("security", &securityConfig); err != nil {
		logger.Info("data.GetSecurityConfigErr", logger.Err(err))
		return err
	}
	cacheClient = cache.NewClient()
	cassandraClient = cassandra.NewClient()
	logger.Info("data.SetupEnd")
	return nil
}

//Authenticator is the data struct of the security authenticato configuration
type Authenticator struct {
	util.JSONObject
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
	util.JSONObject  `json:"-"`
	cassandra.Client `json:"-"`
	Username         string   `json:"username"`
	Name             string   `json:"name"`
	Password         string   `json:"password"`
	Roles            []string `json:"roles"`
}

func (l Login) String() string {
	return fmt.Sprintf("Login[Username=%s Name=%s Roles=%v]", l.Username, l.Name, l.Roles)
}

//CheckCredentials valoidatess if the the parameter is equal of the password field
func (l *Login) CheckCredentials(password string) error {
	return CheckHash(l.Password, password)
}

//Fetch fetchs the Row and sets the values into Login instance
func (l *Login) Fetch(fetchable cassandra.Fetchable) error {
	return fetchable.Scan(&l.Username, &l.Name, &l.Password, &l.Roles)
}

//Read gets the entity representation from the database.
func (l *Login) Read() error {
	if strings.TrimSpace(l.Username) == "" {
		return errors.New("ReadError[Message='Login.Username is empty']")
	}
	err := l.QueryOne("select username, name, password, roles from login where username = ? limit 1", l.Fetch, l.Username)
	if err != nil {
		return err
	}
	return nil
}

//Create adds a new login record to the database.
func (l *Login) Create() error {
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

	err = l.Exec("insert into login (username, name, password, roles) values (?, ?, ?, ?)", l.Username, l.Name, l.Password, l.Roles)
	if err != nil {
		return err
	}
	return nil
}

//Delete removes the login record from the database
func (l *Login) Delete() error {
	if strings.TrimSpace(l.Username) == "" {
		return errors.New("RemoveError: Message='Login.Username is empty'")
	}
	return l.Exec("delete from login where username = ?", l.Username)
}

//Marshal to a JSON representation
func (l *Login) Marshal() ([]byte, error) {
	return l.JSONObject.Marshal(&l)
}

//Unmarshal from a JSON representation
func (l *Login) Unmarshal(reader io.Reader) error {
	return l.JSONObject.Unmarshal(&l, reader)
}

//UnmarshalBytes from a []byte JSON representation
func (l *Login) UnmarshalBytes(data []byte) error {
	return l.JSONObject.UnmarshalBytes(&l, data)
}

//PublicSession represents a public ticket to call the security system
type PublicSession struct {
	util.JSONObject `json:"-"`
	cache.Client    `json:"-"`
	Issuer          string            `json:"iss"`
	ID              string            `json:"id"`
	Username        string            `json:"username"`
	PrivateSession  *identity.Session `json:"privateSession"`
	Token           []byte            `json:"-"`
}

func (s *PublicSession) String() string {
	return fmt.Sprintf("PublicSession[ID=%v Username=%v Issuer=%v PrivateSession=%v]", s.ID, s.Username, s.Issuer, s.PrivateSession)
}

//Set sets the session to cache
func (s *PublicSession) Set() error {
	ttl := int(s.PrivateSession.TTL / time.Second)
	logger.Debug("StoringSession",
		logger.String("ID", s.ID),
		logger.Int("TTL", ttl),
		logger.String("Private", s.PrivateSession.String()),
	)
	sessionBytes, err := s.Marshal()
	if err != nil {
		return fmt.Errorf("MarshalSessionError: Message='ImpossibleToMarshalSession: ID=%v Cause=%v'", s.ID, err)
	}
	err = s.Client.Set(s.ID, ttl, sessionBytes)
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
func (s *PublicSession) Get() error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("data.PublicSession.Get: Message='PublicSession.ID is empty'")
	}
	logger.Info("GetPublicSession", logger.Struct("client", s.Client))
	sessionBytes, err := s.Client.Get(s.ID)
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

//Marshal to a JSON representation
func (s *PublicSession) Marshal() ([]byte, error) {
	return s.JSONObject.Marshal(&s)
}

//Unmarshal from a JSON representation
func (s *PublicSession) Unmarshal(reader io.Reader) error {
	return s.JSONObject.Unmarshal(&s, reader)
}

//UnmarshalBytes from a JSON representation
func (s *PublicSession) UnmarshalBytes(data []byte) error {
	return s.JSONObject.UnmarshalBytes(&s, data)
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
