package identity

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"

	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/config"
	"github.com/valyala/fasthttp"
)

type Handler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	HandleRequest(ctx *fasthttp.RequestCtx)
}

type AuthenticatableHandler interface {
	Handler
	GetSession() *Session
	SetSession(session *Session)
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
		ProxyConfig:            config.Get().Proxy,
		SecurityConfig:         config.Get().Security,
	}
}

type CookieAuthenticatedHandler struct {
	AuthenticatableHandler
	config.ProxyConfig
	config.SecurityConfig
}

func (handler *CookieAuthenticatedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serveUnauthorizedResult := func() {
		log.Info("HandleResult[Status=UnauthorizedRequest Message=401 StatusUnauthorized]")
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
		log.Info("GotCookieValueFromRequest",
			logger.String("Name", handler.SecurityConfig.CookieName),
			logger.String("Value", cookie.Value),
		)
		jwtSessionToken := []byte(cookie.Value)
		session, err := ReadSession(jwtSessionToken)
		log.Info("GotIdentitySession",
			logger.Struct("Session", session),
		)
		if err != nil {
			log.Error("ReadSessionError",
				logger.Error(err),
			)
			serveUnauthorizedResult()
		} else {
			handler.AuthenticatableHandler.SetSession(session)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.ServeHTTP(w, r)
		}
	} else {
		log.Info("ParseCookieError",
			logger.String("Name", handler.SecurityConfig.CookieName),
			logger.Error(err),
		)
		serveUnauthorizedResult()
	}
}

func (handler *CookieAuthenticatedHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	serveUnauthorizedResult := func() {
		log.Info("HandleResult[Status=UnauthorizedRequest Message=401 StatusUnauthorized]")
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
	cookieValue := ctx.Request.Header.Cookie(handler.SecurityConfig.CookieName)
	var cookie fasthttp.Cookie
	err := cookie.ParseBytes(cookieValue)
	if err == nil {
		log.Info("GotCookieValueFromRequest",
			logger.String("Name", handler.SecurityConfig.CookieName),
			logger.String("Value", cookie.String()),
		)
		session, err := ReadSession(cookie.Value())
		log.Info("GotIdentitySession",
			logger.Struct("Session", session),
		)
		if err != nil {
			log.Error("ReadSessionError",
				logger.Error(err),
			)
			serveUnauthorizedResult()
		} else {
			handler.AuthenticatableHandler.SetSession(session)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.HandleRequest(ctx)
		}
	} else {
		log.Info("ParseCookieError",
			logger.String("Name", handler.SecurityConfig.CookieName),
			logger.Error(err),
		)
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
		log.Info("HandleResult[Status=UnauthorizedRequest Message=401 StatusUnauthorized]")
		w.WriteHeader(http.StatusUnauthorized)
	}
	//serveForbiddendResult := func(w http.ResponseWriter, r *http.Request) {
	//    log.Println("ForbiddenRequest: Message[403 StatusForbidden]")
	//    w.WriteHeader(http.StatusForbidden)
	//}
	authorization := r.Header.Get("Authorization")
	log.Info("GotHeaderValueFromRequest",
		logger.String("Authorization", authorization),
	)
	authorizationFields := strings.Fields(authorization)
	if len(authorizationFields) > 1 {
		jwtSessionToken := []byte(authorizationFields[1])
		session, err := ReadSession(jwtSessionToken)
		log.Info("GotIdentitySession",
			logger.Struct("Session", session),
		)
		if err != nil {
			log.Error("ReadSessionError",
				logger.Error(err),
			)
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

func (handler *HeaderAuthenticatedHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	serveUnauthorizedResult := func() {
		log.Info("HandleResult[Status=UnauthorizedRequest Message=401 StatusUnauthorized]")
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	}
	//serveForbiddendResult := func(w http.ResponseWriter, r *http.Request) {
	//    log.Println("ForbiddenRequest: Message[403 StatusForbidden]")
	//    w.WriteHeader(http.StatusForbidden)
	//}
	authorization := ctx.Request.Header.Peek("Authorization")
	log.Info("GotHeaderValueFromRequest",
		logger.Bytes("Authorization", authorization),
	)

	authorizationFields := bytes.Fields(authorization)
	if len(authorizationFields) > 1 {
		jwtToken := authorizationFields[1]
		session, err := ReadSession(jwtToken)
		log.Info("GotIdentitySession",
			logger.Struct("Session", session),
		)
		if err != nil {
			log.Error("ReadSessionError",
				logger.Error(err),
			)
			serveUnauthorizedResult()
		} else {
			handler.AuthenticatableHandler.SetSession(session)
			//r.SetBasicAuth("FFM_ID", ffmId);
			//r.Header.Set("X-FFM_ID", sid)
			handler.AuthenticatableHandler.HandleRequest(ctx)
		}
	} else {
		serveUnauthorizedResult()
	}
}

func NewRequestMethodHandler(get Handler, post Handler) *RequestMethodHandler {
	return &RequestMethodHandler{Get: get, Post: post}
}

func NewFullRequestMethodHandler(g Handler, p Handler, u Handler, d Handler, o Handler, h Handler, t Handler) *RequestMethodHandler {
	return &RequestMethodHandler{Get: g, Post: p, Put: u, Delete: d, Options: o, Head: h, Trace: t}
}

type RequestMethodHandler struct {
	Get     Handler
	Post    Handler
	Put     Handler
	Delete  Handler
	Options Handler
	Head    Handler
	Trace   Handler
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

func (h ProtectedRequestMethodHandler) HandleRequest(ctx *fasthttp.RequestCtx) {
	method := string(ctx.Method())
	switch method {
	case "GET":
		if h.Get != nil {
			h.Get.SetSession(h.session)
			h.Get.HandleRequest(ctx)
		}
	case "POST":
		if h.Post != nil {
			h.Post.SetSession(h.session)
			h.Post.HandleRequest(ctx)
		}
	case "PUT":
		if h.Put != nil {
			h.Put.SetSession(h.session)
			h.Put.HandleRequest(ctx)
		}
	case "DELETE":
		if h.Delete != nil {
			h.Delete.SetSession(h.session)
			h.Delete.HandleRequest(ctx)
		}
	case "OPTIONS":
		if h.Options != nil {
			h.Options.SetSession(h.session)
			h.Options.HandleRequest(ctx)
		}
	case "HEAD":
		if h.Head != nil {
			h.Head.SetSession(h.session)
			h.Head.HandleRequest(ctx)
		}
	case "TRACE":
		if h.Trace != nil {
			h.Trace.SetSession(h.session)
			h.Trace.HandleRequest(ctx)
		}
	default:
		//http.NotFound(w, r)
		ctx.Error("MethodNotAllowed: Method="+method, fasthttp.StatusMethodNotAllowed)
	}
}
