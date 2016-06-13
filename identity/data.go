package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"farm.e-pedion.com/repo/logger"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
)

var (
	log       = logger.GetLogger("identity")
	jwtKey    = []byte("321ewqdsa#@!")
	jwtCrypto = crypto.SigningMethodHS512
)

//NewSession creates a new session from JWT
func NewSession(jwt jwt.JWT) (*Session, error) {
	if jwt == nil {
		return nil, errors.New("JWT is nil")
	}
	log.Debugf("JWTSessionClaims: Claims=%+v", jwt.Claims())
	if !jwt.Claims().Has("iss") || !jwt.Claims().Has("id") || !jwt.Claims().Has("username") || !jwt.Claims().Has("roles") {
		return nil, errors.New("Some required parameter is missing: iss, id, username, roles")
	}
	claimsRoles := jwt.Claims().Get("roles").([]interface{})
	roles := make([]string, len(claimsRoles))
	for k, v := range roles {
		roles[k] = string(v)
	}
	var sessionData map[string]interface{}
	if jwt.Claims().Has("data") {
		sessionData = jwt.Claims().Get("data").(map[string]interface{})
	}
	session := &Session{
		Issuer:   jwt.Claims().Get("iss").(string),
		ID:       jwt.Claims().Get("id").(string),
		Username: jwt.Claims().Get("username").(string),
		Roles:    roles,
		Data:     sessionData,
		//Expires:  time.Unix(int64(jwt.Claims().Get("exp").(float64)), 0),
	}
	return session, nil
}

//ReadSession loads session from JWT Token
func ReadSession(token string) (*Session, error) {
	jwt, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return nil, err
	}
	if err := jwt.Validate(jwtKey, jwtCrypto); err != nil {
		return nil, err
	}
	session, err := NewSession(jwt)
	if err != nil {
		return nil, err
	}
	return session, nil
}

//Session represents a identity session in the system
type Session struct {
	Issuer     string                 `json:"iss"`
	ID         string                 `json:"id"`
	Username   string                 `json:"username"`
	Roles      []string               `json:"roles"`
	CreateDate time.Time              `json:"createDate"`
	TTL        time.Duration          `json:"ttl"`
	Expires    time.Time              `json:"expires"`
	Data       map[string]interface{} `json:"data"`
	Token      []byte                 `json:"-"`
}

func (s *Session) String() string {
	return fmt.Sprintf("Session[Issuer=%v ID=%v Username=%v Roles=%v]", s.Issuer, s.ID, s.Username, s.Roles)
}

//Marshal creates a plain JSON representation of the Session
func (s *Session) Marshal() ([]byte, error) {
	return json.Marshal(&s)
}

//Unmarshal converts the parameter JSON representation into a instance of the Session
func (s *Session) Unmarshal(reader io.Reader) error {
	return json.NewDecoder(reader).Decode(&s)
}

//Serialize writes a JWT representation of this Session in the Token field
func (s *Session) Serialize() error {
	claims := jws.Claims{
		"iss":      s.Issuer,
		"id":       s.ID,
		"username": s.Username,
		"roles":    s.Roles,
	}
	if s.Data != nil {
		claims.Set("data", s.Data)
	}
	//claims.SetIssuer("e-pedion.com")
	jwt := jws.NewJWT(claims, jwtCrypto)
	token, err := jwt.Serialize(jwtKey)
	if err != nil {
		return err
	}
	s.Token = token
	return nil
}
