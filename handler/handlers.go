package handler

import (
	"bytes"
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
	"github.com/valyala/fasthttp"
)

var (
	log = logger.GetLogger()
)

type FastHttpHandler interface {
	HandleRequest(ctx *fasthttp.RequestCtx)
}

type AuthenticatableHandler interface {
	FastHttpHandler
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

func NewSessionCookieHandler(handler AuthenticatableHandler) FastHttpHandler {
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
		log.Info("SessionCookieHandler.ServeHTTP",
			logger.String("Cookie", cookie.String()),
		)
		jwtToken := []byte(cookie.Value)
		publicSession, err := data.ReadSession(jwtToken)
		if err != nil {
			log.Error("handler.SessionCookieHandler.FindSessionError", logger.Error(err))
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

func (handler *SessionCookieHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	serveUnauthorizedResult := func() {
		log.Info("SessionCookieHandler.HandleRequest: UnauthorizedRequest[Message[401 StatusUnauthorized]]")
		apiAcceptRegex := "json|plain"
		accpet := string(ctx.Request.Header.Peek("Accept"))
		if matches, _ := regexp.MatchString(apiAcceptRegex, accpet); matches {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		} else {
			ctx.Redirect(handler.ProxyConfig.LoginURL, fasthttp.StatusFound)
		}
	}
	//serveForbiddendResult := func(w http.ResponseWriter, r *http.Request) {
	//    log.Println("ForbiddenRequest: Message[403 StatusForbidden]")
	//    w.WriteHeader(http.StatusForbidden)
	//}
	cookieData := string(ctx.Request.Header.Cookie(handler.SecurityConfig.CookieName))
	log.Info("SessionCookieHandler.HandleRequest", logger.String("CookieData", cookieData))
	var cookie fasthttp.Cookie
	err := cookie.Parse(cookieData)
	if err == nil {
		log.Info("SessionCookieHandler.HandleRequest", logger.String("Cookie", cookieData))
		publicSession, err := data.ReadSession(cookie.Value())
		if err != nil {
			log.Error("SessionCookieHandler.FindSessionError", logger.Error(err))
			serveUnauthorizedResult()
		} else {
			handler.AuthenticatableHandler.SetSession(publicSession)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.HandleRequest(ctx)
		}
	} else {
		log.Info("SessionCookieHandler.HandleRequestError",
			logger.String("Cookie", cookieData),
			logger.String("Message", cookieData),
			logger.Error(err),
		)
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
	log.Debug("HeaderAuthenticatedHandler.ServeHTTP", logger.String("Authorization", authorization))
	authorizationFields := strings.Fields(authorization)
	if len(authorizationFields) > 1 {
		jwtToken := []byte(authorizationFields[1])
		log.Debug("HeaderAuthenticatedHandler.ServeHTTP", logger.Bytes("SessionToken", jwtToken))
		publicSession, err := data.ReadSession(jwtToken)
		if err != nil {
			log.Error("identity.AuthenticatedHandler.FindSessionError", logger.Error(err))
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

func (handler *SessionHeaderHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	serveUnauthorizedResult := func() {
		log.Info("UnauthorizedRequest[Message='401 StatusUnauthorized']")
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	}
	//serveForbiddendResult := func(w http.ResponseWriter, r *http.Request) {
	//    log.Println("ForbiddenRequest: Message[403 StatusForbidden]")
	//    w.WriteHeader(http.StatusForbidden)
	//}
	authorization := ctx.Request.Header.Peek("Authorization")
	log.Debug("RequestHeader", logger.Bytes("Authorization", authorization))
	authorizationFields := bytes.Fields(authorization)
	if len(authorizationFields) > 1 {
		jwtToken := authorizationFields[1]
		log.Debug("SessionToken", logger.Bytes("Value", jwtToken))
		publicSession, err := data.ReadSession(jwtToken)
		if err != nil {
			log.Error("FindSessionError", logger.Error(err))
			serveUnauthorizedResult()
		} else {
			handler.AuthenticatableHandler.SetSession(publicSession)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.HandleRequest(ctx)
		}
	} else {
		serveUnauthorizedResult()
	}
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{
		ProxyConfig:    config.BindProxyConfiguration(),
		SecurityConfig: config.BindSecurityConfiguration(),
	}
}

type AuthHandler struct {
	*config.ProxyConfig
	*config.SecurityConfig
}

func (l *AuthHandler) renderLoginPage(ctx *fasthttp.RequestCtx, parameters data.LoginPageData) {
	ctx.SetContentType("text/html; charset=utf-8")
	asset.WriteBody(ctx, parameters)
	asset.WriteFoorter(ctx, parameters)
}

func (l *AuthHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	log.Debug("LoginHandler.ServeHTTP",
		logger.Bytes("Method", ctx.Method()),
		logger.String("URI", ctx.URI().String()),
		logger.Bytes("HOST", ctx.Host()),
	)
	method := ctx.Method()
	if bytes.Equal(method, []byte("GET")) {
		parameters := data.LoginPageData{
			LoginUserData: data.LoginUserData{
				RemmenberUser:     true,
				FormURI:           l.ProxyConfig.FormURI,
				FormUsernameField: l.ProxyConfig.FormUsernameField,
				FormPasswordField: l.ProxyConfig.FormPasswordField,
			},
		}
		l.renderLoginPage(ctx, parameters)
		//log.Printf("LoginHandler.GetAuthPage: Method[GET] URL[%v] HOST[%v] Headers[%q]", r.URL, r.Host, r.Header)
		log.Debug("LoginHandler.GetAuthPage Method=GET",
			logger.String("URI", ctx.URI().String()),
			logger.Bytes("HOST", ctx.Host()),
		)
	} else if bytes.Equal(method, []byte("POST")) {
		resultContentNegotiator := func(err error) {
			apiAcceptRegex := "json|plain"
			accept := string(ctx.Request.Header.Peek("Accept"))
			log.Info("LoginHandler.ContentNegotiator",
				logger.String("ApiAcceptRegex", apiAcceptRegex),
				logger.String("Accept", accept),
			)
			if matches, _ := regexp.MatchString(apiAcceptRegex, accept); matches {
				if err == nil {
					ctx.SetStatusCode(fasthttp.StatusOK)
					//w.WriteHeader(http.StatusOK)
				} else {
					ctx.SetStatusCode(fasthttp.StatusUnauthorized)
					//w.WriteHeader(http.StatusUnauthorized)
				}
			} else {
				if err == nil {
					ctx.Redirect(l.ProxyConfig.RedirectURL, fasthttp.StatusFound)
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
					l.renderLoginPage(ctx, parameters)
				}
			}
		}
		//log.Printf("LoginHandler.CreatingSession: Method[POST] URL[%v] HOST[%v] Headers[%q]", r.URL, r.Host, r.Header)
		log.Info("LoginHandler.CreatingSession Method=POST",
			logger.String("URI", ctx.URI().String()),
			logger.Bytes("HOST", ctx.Host()),
		)
		//Dummy credentials
		username := string(ctx.FormValue(l.ProxyConfig.FormUsernameField))
		password := string(ctx.FormValue(l.ProxyConfig.FormPasswordField))
		session, err := data.Authenticate(username, password)
		if err != nil {
			log.Error("LoginHandler.AuthenticationFailed",
				logger.String("Username", username),
				logger.String("Password", password),
				logger.Error(err),
			)
			resultContentNegotiator(err)
			return
		}
		log.Debug("LoginHandler.SessionExpires",
			logger.String("SessionId", session.ID),
			logger.Time("Now", time.Now()),
			logger.Time("Expires", session.PrivateSession.Expires),
		)
		var cookie fasthttp.Cookie
		cookie.SetKey(l.SecurityConfig.CookieName)
		//Name:    l.SecurityConfig.CookieName,
		cookie.SetValueBytes(session.Token)
		//Value:   string(session.Token),
		//cookie.SetDomain(l.SecurityConfig.CookieDomain)
		//Domain:  l.SecurityConfig.CookieDomain,
		cookie.SetPath(l.SecurityConfig.CookiePath)
		//Path:    l.SecurityConfig.CookiePath,
		cookie.SetExpire(session.PrivateSession.Expires)
		//Expires: session.PrivateSession.Expires,

		ctx.Response.Header.SetCookie(&cookie)
		//r.AddCookie(cookie)
		ctx.Response.Header.Set(fmt.Sprintf("X-%v", l.SecurityConfig.CookieName), string(session.Token))
		//w.Header().Set(fmt.Sprintf("X-%v", l.SecurityConfig.CookieName), string(session.Token))
		log.Info("LoginHandler.CreatedSession",
			logger.String("SessionId", session.ID),
			logger.Bytes("Cookie", cookie.Cookie()),
			logger.String("URI", ctx.URI().String()),
		)
		resultContentNegotiator(nil)
	}
}

func NewLogoutHandler() FastHttpHandler {
	return &SessionCookieHandler{
		AuthenticatableHandler: &LogoutHandler{
			SecurityConfig: config.BindSecurityConfiguration(),
			ProxyConfig:    config.BindProxyConfiguration(),
		},
		ProxyConfig:    config.BindProxyConfiguration(),
		SecurityConfig: config.BindSecurityConfiguration(),
	}
	// return &LogoutHandler{
	// 	SecurityConfig: config.BindSecurityConfiguration(),
	// 	ProxyConfig:    config.BindProxyConfiguration(),
	// }
}

type LogoutHandler struct {
	AuthenticatedHandler
	*config.SecurityConfig
	*config.ProxyConfig
}

func (l *LogoutHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	privateSession := l.GetSession().PrivateSession
	log.Info("LogoutHandler.SessionFound", logger.String(privateSession.ID, privateSession.Username))
	nowTime := time.Now()
	expiresTime := nowTime.AddDate(0, 0, -1)
	//log.Infof("LogoutHandler.CookieExpires: Session[%v=%v] Now[%v] Expires[%v]", privateSession.ID, privateSession.Username, nowTime, expiresTime)
	log.Info("LogoutHandler.CookieExpires",
		logger.Time("Now", nowTime),
		logger.Time("Expires", expiresTime),
	)
	var logoutCookie fasthttp.Cookie
	logoutCookie.SetKey(l.SecurityConfig.CookieName)
	logoutCookie.SetDomain(l.SecurityConfig.CookieDomain)
	logoutCookie.SetPath(l.SecurityConfig.CookiePath)
	logoutCookie.SetExpire(expiresTime)
	ctx.Response.Header.SetCookie(&logoutCookie)

	accept := string(ctx.Request.Header.Peek("Accept"))
	if matches, _ := regexp.MatchString("json|plain", accept); matches {
		ctx.SetStatusCode(fasthttp.StatusOK)
		//w.WriteHeader(http.StatusOK)
	} else {
		ctx.Redirect(l.ProxyConfig.RedirectURL, fasthttp.StatusFound)
		//http.Redirect(w, r, l.ProxyConfig.RedirectURL, http.StatusFound)
	}
}

func (l *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	privateSession := l.GetSession().PrivateSession
	log.Info("LogoutHandler.SessionFound", logger.String(privateSession.ID, privateSession.Username))
	nowTime := time.Now()
	expiresTime := nowTime.AddDate(0, 0, -1)
	log.Info("LogoutHandler.CookieExpires",
		logger.String(privateSession.ID, privateSession.Username),
		logger.Time("Now", nowTime),
		logger.Time("Expires", expiresTime),
	)
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

func NewGetSessionHandler() FastHttpHandler {
	return &SessionCookieHandler{
		AuthenticatableHandler: &GetSessionHandler{},
		ProxyConfig:            config.BindProxyConfiguration(),
		SecurityConfig:         config.BindSecurityConfiguration(),
	}
}

type GetSessionHandler struct {
	AuthenticatedHandler
}

func (s *GetSessionHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	method := ctx.Method()
	if bytes.Equal(method, []byte("GET")) {
		privateSession := s.GetSession().PrivateSession
		log.Debug("SessionFound", logger.String(privateSession.ID, privateSession.Username))

		session := s.GetSession()

		jsonData, err := session.Marshal()
		if err != nil {
			log.Error("SessionHandler.WriteResponseError", logger.String("SessionId", session.ID), logger.Error(err))
			ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		}

		ctx.SetContentType("application/json; charset=utf-8")
		ctx.SetStatusCode(fasthttp.StatusOK)
		bytesWritten, err := ctx.Write(jsonData)
		if err != nil {
			log.Error("SessionHandler.WriteResponseError", logger.String("SessionId", session.ID), logger.Error(err))
		} else {
			log.Info("SessionHandler.ResponseWritten", logger.String("SessionId", session.ID), logger.Int("Bytes", bytesWritten))
		}
	}
}

func (h *GetSessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		privateSession := h.GetSession().PrivateSession
		log.Debug("GetSessionHandler.SessionFound", logger.String(privateSession.ID, privateSession.Username))

		urlPathParameters := strings.Split(r.URL.Path, "/")
		log.Debug("SessionHandler.Get",
			logger.String("URI", r.URL.Path),
			logger.Struct("PathParameters", urlPathParameters),
			logger.String("JobId", urlPathParameters[3]),
		)

		session := h.GetSession()

		jsonData, err := session.Marshal()
		if err != nil {
			log.Error("SessionHandler.WriteResponseError", logger.String("SessionId", session.ID), logger.Error(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		bytesWritten, err := w.Write(jsonData)
		if err != nil {
			log.Error("SessionHandler.WriteResponseError", logger.String("SessionID", session.ID), logger.Error(err))
		} else {
			log.Info("SessionHandler.ResponseWritten", logger.String("SessionId", session.ID), logger.Int("Bytes", bytesWritten))
		}
	}
}

func NewValidateSessionHandler() FastHttpHandler {
	return &SessionCookieHandler{
		AuthenticatableHandler: &ValidateSessionHandler{},
		ProxyConfig:            config.BindProxyConfiguration(),
		SecurityConfig:         config.BindSecurityConfiguration(),
	}
}

type ValidateSessionHandler struct {
	AuthenticatedHandler
}

func (v *ValidateSessionHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	method := string(ctx.Method())
	session := v.GetSession()
	privateSession := session.PrivateSession
	log.Debug("HandleRequest.ValidateSessionOK",
		logger.String("Method", method),
		logger.String("PublicID", session.ID),
		logger.String("PrivateID", privateSession.ID),
		logger.String("Username", privateSession.Username),
	)

	ctx.SetContentType("text/plain; charset=utf-8")
	ctx.Response.Header.Set("Content-Length", "0")
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (v *ValidateSessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.Method
	session := v.GetSession()
	privateSession := session.PrivateSession
	log.Debug("ServeHTTP.ValidateSessionOK",
		logger.String("Method", method),
		logger.String("PublicID", session.ID),
		logger.String("PrivateID", privateSession.ID),
		logger.String("Username", privateSession.Username),
	)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

func NewLoginManagerHandler() FastHttpHandler {
	return NewRequestMethodHandler(
		&SessionCookieHandler{
			AuthenticatableHandler: &GetLoginHandler{},
			ProxyConfig:            config.BindProxyConfiguration(),
			SecurityConfig:         config.BindSecurityConfiguration(),
		},
		&SessionCookieHandler{
			AuthenticatableHandler: &PostLoginHandler{},
			ProxyConfig:            config.BindProxyConfiguration(),
			SecurityConfig:         config.BindSecurityConfiguration(),
		})
}

type GetLoginHandler struct {
	AuthenticatedHandler
}

func (h *GetLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlPathParameters := strings.Split(r.URL.Path, "/")
	log.Debug("GetUsernHandler.Get",
		logger.String("URL", r.URL.Path),
		logger.Struct("PathParameters", urlPathParameters),
		logger.String("JobId", urlPathParameters[3]),
	)
	username := urlPathParameters[3]

	login := data.Login{Username: username}
	if err := login.Read(); err != nil {
		log.Error("handler.GetLoginHandler.ReadLoginError", logger.String("Username", username), logger.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonData, err := json.Marshal(login)
	if err != nil {
		log.Error("handler.GetLoginHandler.WriteResponseError", logger.String("Username", username), logger.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	bytesWritten, err := w.Write(jsonData)
	if err != nil {
		log.Error("GetUserHandler.WriteResponseError", logger.String("Username", username), logger.Error(err))
	} else {
		log.Info("GetUserHandler.ResponseWritten", logger.String("Username", username), logger.Int("Bytes", bytesWritten))
	}
}

func (h *GetLoginHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	log.Debug("GetUsernHandler", logger.String("URI", ctx.URI().String()))
	username := string(ctx.URI().LastPathSegment())

	login := data.Login{Username: username}
	if err := login.Read(); err != nil {
		log.Error("ReadLoginError", logger.String("Username", username), logger.Error(err))
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}

	jsonData, err := json.Marshal(login)
	if err != nil {
		log.Error("handler.GetLoginHandler.WriteResponseError", logger.String("Username", username), logger.Error(err))
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetContentType("application/json; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusOK)
	bytesWritten, err := ctx.Write(jsonData)
	if err != nil {
		log.Error("WriteResponseError", logger.String("Username", username), logger.Error(err))
	} else {
		log.Info("ResponseWritten", logger.String("Username", username), logger.Int("Bytes", bytesWritten))
	}
}

type PostLoginHandler struct {
	AuthenticatedHandler
}

func (h *PostLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	login := data.Login{}
	if err := login.Unmarshal(r.Body); err != nil {
		log.Error("PostLoginHandler.PostLoginError", logger.Error(err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		if err := login.Create(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			//w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)
		}
	}
}

func (h *PostLoginHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	login := data.Login{}
	if err := login.UnmarshalBytes(ctx.PostBody()); err != nil {
		log.Error("PostLoginHandlerDecodeError", logger.Error(err))
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	log.Debug("PostLoginHandler", logger.String("Login", login.String()))
	if err := login.Create(); err != nil {
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	//w.Header().Set("Content-Type", "application/json; charset=utf-8")
	ctx.SetStatusCode(fasthttp.StatusCreated)
}

func NewRequestMethodHandler(get AuthenticatableHandler, post AuthenticatableHandler) *RequestMethodHandler {
	return &RequestMethodHandler{Get: get, Post: post}
}

func NewFullRequestMethodHandler(g AuthenticatableHandler, p AuthenticatableHandler, u AuthenticatableHandler, d AuthenticatableHandler, o AuthenticatableHandler, h AuthenticatableHandler, t AuthenticatableHandler) *RequestMethodHandler {
	return &RequestMethodHandler{Get: g, Post: p, Put: u, Delete: d, Options: o, Head: h, Trace: t}
}

//RequestMethodHandler delegates the request by the provided http method
type RequestMethodHandler struct {
	Get     AuthenticatableHandler
	Post    AuthenticatableHandler
	Put     AuthenticatableHandler
	Delete  AuthenticatableHandler
	Options AuthenticatableHandler
	Head    AuthenticatableHandler
	Trace   AuthenticatableHandler
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

func (h RequestMethodHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	method := string(ctx.Method())
	switch method {
	case "GET":
		if h.Get != nil {
			h.Get.HandleRequest(ctx)
		}
	case "POST":
		if h.Post != nil {
			h.Post.HandleRequest(ctx)
		}
	case "PUT":
		if h.Put != nil {
			h.Put.HandleRequest(ctx)
		}
	case "DELETE":
		if h.Delete != nil {
			h.Delete.HandleRequest(ctx)
		}
	case "OPTIONS":
		if h.Options != nil {
			h.Options.HandleRequest(ctx)
		}
	case "HEAD":
		if h.Head != nil {
			h.Head.HandleRequest(ctx)
		}
	case "TRACE":
		if h.Trace != nil {
			h.Trace.HandleRequest(ctx)
		}
	default:
		//http.NotFound(w, r)
		ctx.Error("MethodNotAllowed: Method="+method, fasthttp.StatusMethodNotAllowed)
	}
}
