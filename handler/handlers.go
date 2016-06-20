package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/data"

	"farm.e-pedion.com/repo/security/asset"
)

var (
	log = logger.GetLogger("handler")
)

type AuthenticatableHandler interface {
	SetSession(session *data.PublicSession)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

type AuthenticatedHandler struct {
	session *data.PublicSession
}

func (p *AuthenticatedHandler) SetSession(session *data.PublicSession) {
	p.session = session
}

func (p *AuthenticatedHandler) GetSession() *data.PublicSession {
	return p.session
}

func NewSessionCookieHandler(handler AuthenticatableHandler) http.Handler {
	return &SessionCookieHandler{
		AuthenticatableHandler: handler,
		ProxyConfig:            config.BindProxyConfiguration(),
		SecurityConfig:         config.BindSecurityConfiguration(),
	}
}

type SessionCookieHandler struct {
	AuthenticatableHandler
	*config.ProxyConfig
	*config.SecurityConfig
}

func (handler *SessionCookieHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serveUnauthorizedResult := func() {
		log.Info("CookieAuthenticatedHandler.ServeHTTP: UnauthorizedRequest[Message[401 StatusUnauthorized]]")
		apiAcceptRegex := "json|plain"
		accpet := r.Header.Get("Accept")
		if matches, _ := regexp.MatchString(apiAcceptRegex, accpet); matches {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			http.Redirect(w, r, handler.ProxyConfig.LoginURL, http.StatusFound)
		}
	}
	//serveForbiddendResult := func(w http.ResponseWriter, r *http.Request) {
	//    log.Println("ForbiddenRequest: Message[403 StatusForbidden]")
	//    w.WriteHeader(http.StatusForbidden)
	//}
	cookie, err := r.Cookie(handler.SecurityConfig.CookieName)
	if err == nil {
		log.Info("SessionCookieHandler.ServeHTTP: Cookie[%v]", cookie.String())
		jwtToken := cookie.Value
		publicSession, err := data.ReadSession(jwtToken)
		if err != nil {
			log.Errorf("handler.SessionCookieHandler.FindSessionError: Error[%v]", err)
			serveUnauthorizedResult()
		} else {
			handler.AuthenticatableHandler.SetSession(publicSession)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.ServeHTTP(w, r)
		}
	} else {
		serveUnauthorizedResult()
	}
}

func NewSessionHeaderHandler(handler AuthenticatableHandler) http.Handler {
	return &SessionHeaderHandler{AuthenticatableHandler: handler}
}

type SessionHeaderHandler struct {
	AuthenticatableHandler
}

func (handler *SessionHeaderHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serveUnauthorizedResult := func(w http.ResponseWriter, r *http.Request) {
		log.Info("UnauthorizedRequest: Message[401 StatusUnauthorized]")
		w.WriteHeader(http.StatusUnauthorized)
	}
	//serveForbiddendResult := func(w http.ResponseWriter, r *http.Request) {
	//    log.Println("ForbiddenRequest: Message[403 StatusForbidden]")
	//    w.WriteHeader(http.StatusForbidden)
	//}
	authorization := r.Header.Get("Authorization")
	log.Debugf("HeaderAuthenticatedHandler.ServeHTTP: Authorization[%v]", authorization)
	authorizationFields := strings.Fields(authorization)
	if len(authorizationFields) > 1 {
		jwtToken := authorizationFields[1]
		log.Debugf("HeaderAuthenticatedHandler.ServeHTTP: SessionToken[%v]", jwtToken)
		publicSession, err := data.ReadSession(jwtToken)
		if err != nil {
			log.Errorf("identity.AuthenticatedHandler.FindSessionError: Error[%v]", err)
			serveUnauthorizedResult(w, r)
		} else {
			handler.AuthenticatableHandler.SetSession(publicSession)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.ServeHTTP(w, r)
		}
	} else {
		serveUnauthorizedResult(w, r)
	}
}

func NewLoginHandler() *LoginHandler {
	return &LoginHandler{
		ProxyConfig:    config.BindProxyConfiguration(),
		SecurityConfig: config.BindSecurityConfiguration(),
	}
}

type LoginHandler struct {
	*config.ProxyConfig
	*config.SecurityConfig
}

func (l *LoginHandler) renderLoginPage(w http.ResponseWriter, parameters data.LoginPageData) {
	asset.WriteBody(w, parameters)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	} else {
		log.Warningf("ResponseWriterIsNotFlusher: ")
	}
	asset.WriteFoorter(w, parameters)
}

func (l *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Debugf("LoginHandler.ServeHTTP: Method[%v] URL[%v] HOST[%v]", r.Method, r.URL, r.Host)
	if r.Method == "GET" {
		parameters := data.LoginPageData{
			LoginUserData: data.LoginUserData{
				RemmenberUser:     true,
				FormURI:           l.ProxyConfig.FormURI,
				FormUsernameField: l.ProxyConfig.FormUsernameField,
				FormPasswordField: l.ProxyConfig.FormPasswordField,
			},
		}
		l.renderLoginPage(w, parameters)
		//log.Printf("LoginHandler.GetAuthPage: Method[GET] URL[%v] HOST[%v] Headers[%q]", r.URL, r.Host, r.Header)
		log.Debugf("LoginHandler.GetAuthPage: Method[GET] URL[%v] HOST[%v]", r.URL, r.Host)
	} else if r.Method == "POST" {
		resultContentNegotiator := func(err error) {
			apiAcceptRegex := "json|plain"
			accept := r.Header.Get("Accept")
			log.Infof("LoginHandler.ContentNegotiator: ApiAcceptRegex[%v] Accept[%v]", apiAcceptRegex, accept)
			if matches, _ := regexp.MatchString(apiAcceptRegex, accept); matches {
				if err == nil {
					w.WriteHeader(http.StatusOK)
				} else {
					w.WriteHeader(http.StatusUnauthorized)
				}
			} else {
				if err == nil {
					http.Redirect(w, r, l.ProxyConfig.RedirectURL, http.StatusFound)
				} else {
					parameters := data.LoginPageData{
						MessageType: "Error",
						Message:     "Invalid credentials",
						LoginUserData: data.LoginUserData{
							RemmenberUser:     true,
							FormURI:           l.ProxyConfig.FormURI,
							FormUsernameField: l.ProxyConfig.FormUsernameField,
							FormPasswordField: l.ProxyConfig.FormPasswordField,
						},
					}
					l.renderLoginPage(w, parameters)
				}
			}
		}
		//log.Printf("LoginHandler.CreatingSession: Method[POST] URL[%v] HOST[%v] Headers[%q]", r.URL, r.Host, r.Header)
		log.Infof("LoginHandler.CreatingSession: Method[POST] URL[%v] HOST[%v]", r.URL, r.Host)
		//Dummy credentials
		username := r.FormValue(l.ProxyConfig.FormUsernameField)
		password := r.FormValue(l.ProxyConfig.FormPasswordField)
		session, err := data.Authenticate(username, password)
		if err != nil {
			log.Errorf("LoginHandler.AuthenticationFailed: Username[%v] Password[%v] Error[%v]", username, password, err)
			resultContentNegotiator(err)
			return
		}
		log.Debugf("LoginHandler.SessionExpires: SessionId[%v] Now[%v] Expires[%v]", session.ID, time.Now(), session.PrivateSession.Expires)
		cookie := &http.Cookie{
			Name:    l.SecurityConfig.CookieName,
			Value:   string(session.Token),
			Domain:  l.SecurityConfig.CookieDomain,
			Path:    l.SecurityConfig.CookiePath,
			Expires: session.PrivateSession.Expires,
		}
		http.SetCookie(w, cookie)
		r.AddCookie(cookie)
		w.Header().Set(fmt.Sprintf("X-%v", l.SecurityConfig.CookieName), string(session.Token))
		log.Infof("LoginHandler.CreatedSession: SessionId[%v] Cookie[%v] URL[%v]", session.ID, cookie, r.URL)
		resultContentNegotiator(nil)
	}
}

func NewLogoutHandler() http.Handler {
	return &SessionCookieHandler{
		AuthenticatableHandler: &LogoutHandler{
			SecurityConfig: config.BindSecurityConfiguration(),
			ProxyConfig:    config.BindProxyConfiguration(),
		},
		ProxyConfig:    config.BindProxyConfiguration(),
		SecurityConfig: config.BindSecurityConfiguration(),
	}
}

type LogoutHandler struct {
	AuthenticatedHandler
	*config.SecurityConfig
	*config.ProxyConfig
}

func (l *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	privateSession := l.GetSession().PrivateSession
	log.Infof("LogoutHandler.SessionFound: %v=%v", privateSession.ID, privateSession.Username)
	nowTime := time.Now()
	expiresTime := nowTime.AddDate(0, 0, -1)
	log.Infof("LogoutHandler.CookieExpires: Session[%v=%v] Now[%v] Expires[%v]", privateSession.ID, privateSession.Username, nowTime, expiresTime)
	cookieExpired := &http.Cookie{
		Name:    l.SecurityConfig.CookieName,
		Domain:  l.SecurityConfig.CookieDomain,
		Path:    l.SecurityConfig.CookiePath,
		Expires: expiresTime,
	}
	http.SetCookie(w, cookieExpired)
	if matches, _ := regexp.MatchString("json|plain", r.Header.Get("Accept")); matches {
		w.WriteHeader(http.StatusOK)
	} else {
		http.Redirect(w, r, l.ProxyConfig.RedirectURL, http.StatusFound)
	}
}

func NewGetSessionHandler() http.Handler {
	return &SessionCookieHandler{
		AuthenticatableHandler: &GetSessionHandler{},
		ProxyConfig:            config.BindProxyConfiguration(),
		SecurityConfig:         config.BindSecurityConfiguration(),
	}
}

type GetSessionHandler struct {
	AuthenticatedHandler
}

func (h *GetSessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		privateSession := h.GetSession().PrivateSession
		log.Debugf("GetSessionHandler.SessionFound: %v=%v", privateSession.ID, privateSession.Username)

		urlPathParameters := strings.Split(r.URL.Path, "/")
		log.Debugf("SessionHandler.Get: URL[%q] PathParameters[%q] JobId[%v]!", r.URL.Path, urlPathParameters, urlPathParameters[3])

		session := h.GetSession()

		jsonData, err := session.Marshal()
		if err != nil {
			log.Errorf("SessionHandler.WriteResponseError: SessionId[%v] Error[%v]", session.ID, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		bytesWritten, err := w.Write(jsonData)
		if err != nil {
			log.Errorf("SessionHandler.WriteResponseError: SessionId[%v] Error[%v]", session.ID, err)
		} else {
			log.Infof("SessionHandler.ResponseWritten: SessionId[%v] Bytes[%v]", session.ID, bytesWritten)
		}
	}
}

func NewLoginManagerHandler() http.Handler {
	return NewRequestMethodHandler(
		&SessionCookieHandler{
			AuthenticatableHandler: &GetLoginHandler{},
			ProxyConfig:            config.BindProxyConfiguration(),
			SecurityConfig:         config.BindSecurityConfiguration(),
		},
		&SessionCookieHandler{
			AuthenticatableHandler: &PostUserHandler{},
			ProxyConfig:            config.BindProxyConfiguration(),
			SecurityConfig:         config.BindSecurityConfiguration(),
		})
}

type GetLoginHandler struct {
	AuthenticatedHandler
}

func (h *GetLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlPathParameters := strings.Split(r.URL.Path, "/")
	log.Debugf("GetUsernHandler.Get: URL[%q] PathParameters[%q] JobId[%v]!", r.URL.Path, urlPathParameters, urlPathParameters[3])
	username := urlPathParameters[3]

	login := data.Login{Username: username}
	if err := login.Read(); err != nil {
		log.Errorf("handler.GetLoginHandler.ReadLoginError: Username[%v] Error[%v]", username, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonData, err := json.Marshal(login)
	if err != nil {
		log.Errorf("handler.GetLoginHandler.WriteResponseError: Username[%v] Error[%v]", username, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	bytesWritten, err := w.Write(jsonData)
	if err != nil {
		log.Errorf("GetUserHandler.WriteResponseError: Username[%v] Error[%v]", username, err)
	} else {
		log.Infof("GetUserHandler.ResponseWritten: Username[%v] Bytes[%v]", username, bytesWritten)
	}
}

type PostUserHandler struct {
	AuthenticatedHandler
}

func (h *PostUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	login := data.Login{}
	if err := login.Unmarshal(r.Body); err != nil {
		log.Errorf("handler.PostLoginHandler.PostLoginError: Error[%v]", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		if err := login.Persist(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			//w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)
		}
	}
}

func NewRequestMethodHandler(get http.Handler, post http.Handler) *RequestMethodHandler {
	return &RequestMethodHandler{Get: get, Post: post}
}

func NewFullRequestMethodHandler(g http.Handler, p http.Handler, u http.Handler, d http.Handler, o http.Handler, h http.Handler, t http.Handler) *RequestMethodHandler {
	return &RequestMethodHandler{Get: g, Post: p, Put: u, Delete: d, Options: o, Head: h, Trace: t}
}

//RequestMethodHandler delegates the request by the provided http method
type RequestMethodHandler struct {
	Get     http.Handler
	Post    http.Handler
	Put     http.Handler
	Delete  http.Handler
	Options http.Handler
	Head    http.Handler
	Trace   http.Handler
}

func (h RequestMethodHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if h.Get != nil {
			h.Get.ServeHTTP(w, r)
		}
	case "POST":
		if h.Post != nil {
			h.Post.ServeHTTP(w, r)
		}
	case "PUT":
		if h.Put != nil {
			h.Put.ServeHTTP(w, r)
		}
	case "DELETE":
		if h.Delete != nil {
			h.Delete.ServeHTTP(w, r)
		}
	case "OPTIONS":
		if h.Options != nil {
			h.Options.ServeHTTP(w, r)
		}
	case "HEAD":
		if h.Head != nil {
			h.Head.ServeHTTP(w, r)
		}
	case "TRACE":
		if h.Trace != nil {
			h.Trace.ServeHTTP(w, r)
		}
	default:
		//http.NotFound(w, r)
		http.Error(w, "identity.RequestMethodHandler.MethodNotAllowed: Method="+r.Method, http.StatusMethodNotAllowed)
	}
}
