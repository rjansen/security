package identity

import (
    "database/sql"
    "fmt"
    "log"
    "time"
    "errors"
    "strings"
    "golang.org/x/crypto/bcrypt"
    "farm.e-pedion.com/repo/security/database"
)

var (
    memoryCache = make(map[string]*Session)
)

//ReadLogin loads the login representation of the username provided
func ReadLogin(username string) (*Login, error) {
    login := &Login{Username: username}
    if err := login.Read(); err != nil {
        return nil, err
    }
    return login, nil
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
    database.SQLSupport
    Username string `json:"username"`
    Name string `json:"name"`
    Password string `json:"password"`
    Roles []string `json:"roles"`
}

//CheckCredentials valoidatess if the the parameter is equal of the password field
func (l *Login) CheckCredentials(password string) error {
    return CheckHash(l.Username, password)
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

//ReadSession loads session from cache
func ReadSession(id string) (*Session, error) {
    session := memoryCache[id]
    if session == nil {
        return nil, fmt.Errorf("identity.SessionNotFound: Message='SessionInvalid: ID=%v'", id)
    }
    if err := session.Refresh(); err != nil {
        return nil, err
    }
    return session, nil
}

//Session represents a identity session in the system
type Session struct {
    database.JSONObject
    ID string `json:"id"`
    Token string `json:"token"`
    CreateDate time.Time `json:"createDate"`
    TTL int `json:"ttl"`
    Expires time.Time `json:"expires"`
    Username string `json:"username"`
    Roles []string `json:"roles"`
}

//Set sets the session to cache
func (s *Session) Set() error {
    memoryCache[s.ID] = s
    return nil
}

//Refresh refreshs the session data
func (s *Session) Refresh() error {
    return nil
}