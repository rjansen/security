package data

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"farm.e-pedion.com/repo/cache"
	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/security/database"
	"farm.e-pedion.com/repo/security/identity"
	"farm.e-pedion.com/repo/security/util"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

const (
	day = 24 * time.Hour
)

var (
	//memoryCache    = make(map[string]*identity.Session)
	jwtKey         = []byte("321ewqdsa#@!")
	jwtCrypto      = crypto.SigningMethodHS512
	proxyConfig    = config.BindProxyConfiguration()
	securityConfig = config.BindSecurityConfiguration()
	cacheClient    = cache.NewClient()
)

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
	ttl := int(s.PrivateSession.TTL / time.Second)
	log.Printf("data.StoreSession: ID=%v TTL=%v Session=%+v", s.ID, ttl, s.PrivateSession)
	sessionBytes, err := json.Marshal(s.PrivateSession)
	if err != nil {
		return fmt.Errorf("data.MarshalSessionError: Message='ImpossibleToMarshalSession: ID=%v Cause=%v'", s.ID, err.Error())
	}
	err = cacheClient.Set(s.ID, ttl, sessionBytes)
	if err != nil {
		return fmt.Errorf("data.SetSessionError: Message='ImpossibleToCacheSession: ID=%v Cause=%v'", s.ID, err.Error())
	}
	log.Printf("data.SessionStored: ID=%v TTL=%v Value=%+v", s.ID, ttl, string(sessionBytes))
	return nil
}

//Get gets the session from cache
func (s *PublicSession) Get() error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("data.PublicSession.Get: Message='PublicSession.ID is empty'")
	}
	log.Printf("data.PublicSession.LoadSessionFromCache: ID=%v", s.ID)
	sessionBytes, err := cacheClient.Get(s.ID)
	if err != nil {
		return fmt.Errorf("data.GetSessionError: Message='ImpossibleToGetCachedSession: ID=%v Cause=%v'", s.ID, err.Error())
	}
	log.Printf("data.PublicSession.SessionLoadedFromCache: ID=%v Value=%+v", s.ID, string(sessionBytes))
	privateSession := &identity.Session{}
	err = json.Unmarshal(sessionBytes, &privateSession)
	if err != nil {
		return fmt.Errorf("data.UnmarshalSessionError: Message='ImpossibleToUnmarshalSession: ID=%v Cause=%v'", s.ID, err.Error())
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
