package identity

import (
	"log"
	"net/http"
	"regexp"
	"strings"

	"farm.e-pedion.com/repo/config"
)

type AuthenticatableHandler interface {
    GetSession() *Session
	SetSession(session *Session)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

type AuthenticatedHandler struct {
	session *Session
}

func (p *AuthenticatedHandler) SetSession(session *Session) {
	p.session = session
}

func (p *AuthenticatedHandler) GetSession() *Session {
	return p.session
}

func NewCookieAuthenticatedHandler(handler AuthenticatableHandler) http.Handler {
	return &CookieAuthenticatedHandler{
		AuthenticatableHandler: handler,
		ProxyConfig:            config.BindProxyConfiguration(),
		SecurityConfig:         config.BindSecurityConfiguration(),
	}
}

type CookieAuthenticatedHandler struct {
	AuthenticatableHandler
	*config.ProxyConfig
	*config.SecurityConfig
}

func (handler *CookieAuthenticatedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serveUnauthorizedResult := func() {
		log.Println("identity.CookieAuthenticatedHandler.ServeHTTP: UnauthorizedRequest[Message[401 StatusUnauthorized]]")
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
		log.Printf("identity.CookieAuthenticatedHandler.ServeHTTP: Cookie[%v]", cookie.String())
		jwtSessionToken := cookie.Value
		log.Printf("identity.CookieAuthenticatedHandler.ServeHTTP: SessionToken[%v]", jwtSessionToken)
		session, err := ReadSession(jwtSessionToken)
		if err != nil {
			log.Printf("identity.CookieAuthenticatedHandler.FindSessionError: Error[%v]", err)
			serveUnauthorizedResult()
		} else {
			handler.AuthenticatableHandler.SetSession(session)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.ServeHTTP(w, r)
		}
	} else {
		serveUnauthorizedResult()
	}
}

func NewHeaderAuthenticatedHandler(handler AuthenticatableHandler) http.Handler {
	return &HeaderAuthenticatedHandler{AuthenticatableHandler: handler}
}

type HeaderAuthenticatedHandler struct {
	AuthenticatableHandler
}

func (handler *HeaderAuthenticatedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serveUnauthorizedResult := func(w http.ResponseWriter, r *http.Request) {
		log.Println("identity.UnauthorizedRequest: Message[401 StatusUnauthorized]")
		w.WriteHeader(http.StatusUnauthorized)
	}
	//serveForbiddendResult := func(w http.ResponseWriter, r *http.Request) {
	//    log.Println("ForbiddenRequest: Message[403 StatusForbidden]")
	//    w.WriteHeader(http.StatusForbidden)
	//}
	authorization := r.Header.Get("Authorization")
	log.Printf("identity.HeaderAuthenticatedHandler.ServeHTTP: Authorization[%v]", authorization)
	authorizationFields := strings.Fields(authorization)
	if len(authorizationFields) > 1 {
		jwtSessionToken := authorizationFields[1]
		log.Printf("identity.HeaderAuthenticatedHandler.ServeHTTP: SessionToken[%v]", jwtSessionToken)
		session, err := ReadSession(jwtSessionToken)
		if err != nil {
			log.Printf("identity.AuthenticatedHandler.FindSessionError: Error[%v]", err)
			serveUnauthorizedResult(w, r)
		} else {
			handler.AuthenticatableHandler.SetSession(session)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.ServeHTTP(w, r)
		}
	} else {
		serveUnauthorizedResult(w, r)
	}
}

func NewRequestMethodHandler(get http.Handler, post http.Handler) *RequestMethodHandler {
	return &RequestMethodHandler{Get: get, Post: post}
}

func NewFullRequestMethodHandler(g http.Handler, p http.Handler, u http.Handler, d http.Handler, o http.Handler, h http.Handler, t http.Handler) *RequestMethodHandler {
	return &RequestMethodHandler{Get: g, Post: p, Put: u, Delete: d, Options: o, Head: h, Trace: t}
}

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

func NewProtectedRequestMethodHandler(get AuthenticatableHandler, post AuthenticatableHandler) *ProtectedRequestMethodHandler {
	return &ProtectedRequestMethodHandler{Get: get, Post: post}
}

func NewFullProtectedRequestMethodHandler(g AuthenticatableHandler, p AuthenticatableHandler, u AuthenticatableHandler, d AuthenticatableHandler, o AuthenticatableHandler, h AuthenticatableHandler, t AuthenticatableHandler) *ProtectedRequestMethodHandler {
	return &ProtectedRequestMethodHandler{Get: g, Post: p, Put: u, Delete: d, Options: o, Head: h, Trace: t}
}

type ProtectedRequestMethodHandler struct {
	AuthenticatedHandler
	Get     AuthenticatableHandler
	Post    AuthenticatableHandler
	Put     AuthenticatableHandler
	Delete  AuthenticatableHandler
	Options AuthenticatableHandler
	Head    AuthenticatableHandler
	Trace   AuthenticatableHandler
}

func (h ProtectedRequestMethodHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if h.Get != nil {
			h.Get.SetSession(h.session)
			h.Get.ServeHTTP(w, r)
		}
	case "POST":
		if h.Post != nil {
			h.Post.SetSession(h.session)
			h.Post.ServeHTTP(w, r)
		}
	case "PUT":
		if h.Put != nil {
			h.Put.SetSession(h.session)
			h.Put.ServeHTTP(w, r)
		}
	case "DELETE":
		if h.Delete != nil {
			h.Delete.SetSession(h.session)
			h.Delete.ServeHTTP(w, r)
		}
	case "OPTIONS":
		if h.Options != nil {
			h.Options.SetSession(h.session)
			h.Options.ServeHTTP(w, r)
		}
	case "HEAD":
		if h.Head != nil {
			h.Head.SetSession(h.session)
			h.Head.ServeHTTP(w, r)
		}
	case "TRACE":
		if h.Trace != nil {
			h.Trace.SetSession(h.session)
			h.Trace.ServeHTTP(w, r)
		}
	default:
		//http.NotFound(w, r)
		http.Error(w, "identity.RequestMethodHandler.MethodNotAllowed: Method="+r.Method, http.StatusMethodNotAllowed)
	}
}
