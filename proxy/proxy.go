package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"

	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/config"
	"farm.e-pedion.com/repo/security/handler"
	"farm.e-pedion.com/repo/security/identity"
	"github.com/valyala/fasthttp"
)

var (
	//Create a config way to strip paths while proxy request
	pathRegex, _ = regexp.Compile("^\\/web|^\\/api")
)

func NewApiReverseProxy(targetURL *url.URL) handler.FastHttpHandler {
	return handler.NewSessionCookieHandler(
		&ApiReverseProxy{
			SecurityConfig: config.Config.Security,
			ProxyURL:       targetURL,
			reverseProxy:   httputil.NewSingleHostReverseProxy(targetURL),
			proxyClient: &fasthttp.HostClient{
				Addr: targetURL.Host,
			},
		})
}

type ApiReverseProxy struct {
	handler.AuthenticatedHandler
	identity.SecurityConfig
	ProxyURL     *url.URL
	reverseProxy *httputil.ReverseProxy
	proxyClient  *fasthttp.HostClient
}

func (a *ApiReverseProxy) HandleRequest(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	resp := &ctx.Response
	requestedPath := string(ctx.URI().RequestURI())
	if matchs := pathRegex.MatchString(requestedPath); matchs {
		req.SetRequestURI(pathRegex.ReplaceAllString(requestedPath, ""))
	}
	//Creates a JWT to proxy the request
	session := a.GetSession()
	privateSession := identity.Session{
		Id:       session.ID,
		Username: session.Username,
		Issuer:   session.Issuer,
		Roles:    []string{"e-user"},
		Data:     session.Data,
	}
	token, err := identity.Serialize(privateSession)
	if err != nil {
		logger.Error("ErrSerializingSession", logger.String("session", session.String()))
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s: %s", a.SecurityConfig.CookieName, token))
	logger.Debug("HeaderAuthorizationFoward",
		logger.String(a.SecurityConfig.CookieName, session.ID),
		logger.String("Requested", a.ProxyURL.String()),
		logger.Bytes("Foward", req.RequestURI()),
	)
	if err := a.proxyClient.Do(req, resp); err != nil {
		logger.Error("ApiProxyHandleRequestError",
			logger.String("Path", requestedPath),
			logger.Err(err),
		)
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
	}
}

func (a *ApiReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestedPath := r.URL.Path
	if matchs := pathRegex.MatchString(r.URL.Path); matchs {
		r.URL.Path = pathRegex.ReplaceAllString(r.URL.Path, "")
	}
	//Creates a JWT to proxy the request
	session := a.GetSession()
	token, err := session.Serialize()
	if err != nil {
		logger.Error("ErrSerializingSession", logger.String("session", session.String()))
		return
	}

	//r.SetBasicAuth(a.session.Username, a.session.ID)
	r.Header.Set("Authorization", fmt.Sprintf("%s: %s", a.SecurityConfig.CookieName, token))
	logger.Debug("HeaderAuthorizationFoward",
		logger.String(a.SecurityConfig.CookieName, session.ID),
		logger.String("Requested", requestedPath),
		logger.String("Foward", a.ProxyURL.String()+r.URL.Path),
	)
	a.reverseProxy.ServeHTTP(w, r)
}

func NewWebReverseProxy(targetURL *url.URL) handler.FastHttpHandler {
	return handler.NewSessionCookieHandler(
		&WebReverseProxy{
			SecurityConfig: config.Config.Security,
			ProxyURL:       targetURL,
			reverseProxy:   httputil.NewSingleHostReverseProxy(targetURL),
			proxyClient: &fasthttp.HostClient{
				Addr: targetURL.Host,
			},
		})
}

type WebReverseProxy struct {
	handler.AuthenticatedHandler
	identity.SecurityConfig
	ProxyURL     *url.URL
	reverseProxy *httputil.ReverseProxy
	proxyClient  *fasthttp.HostClient
}

func (a *WebReverseProxy) HandleRequest(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	resp := &ctx.Response
	requestedPath := string(ctx.URI().RequestURI())
	if matchs := pathRegex.MatchString(requestedPath); matchs {
		req.SetRequestURI(pathRegex.ReplaceAllString(requestedPath, ""))
	}
	//Creates a JWT to proxy the request
	session := a.GetSession()
	privateSession := identity.Session{
		Id:       session.ID,
		Username: session.Username,
		Issuer:   session.Issuer,
		Roles:    []string{"e-user"},
		Data:     session.Data,
	}

	token, err := identity.Serialize(privateSession)
	if err != nil {
		logger.Error("ErrSerializingSession", logger.String("session", session.String()))
		return
	}

	var cookie fasthttp.Cookie
	cookie.SetKey(a.SecurityConfig.CookieName)
	cookie.SetValueBytes(token)
	//cookie.SetDomain(l.SecurityConfig.CookieDomain)
	cookie.SetPath(a.SecurityConfig.CookiePath)
	cookie.SetExpire(session.ExpiresAt)

	req.Header.SetCookie(a.SecurityConfig.CookieName, cookie.String())
	//req.Header.Set(fmt.Sprintf("X-%v", a.SecurityConfig.CookieName), string(privateSession.Token))
	logger.Debug("CookieAuthFoward",
		logger.String(a.SecurityConfig.CookieName, session.ID),
		logger.String("Requested", requestedPath),
		logger.Bytes("Foward", append([]byte(a.ProxyURL.String()), 'c')),
	)
	if err := a.proxyClient.Do(req, resp); err != nil {
		logger.Error("ApiProxyHandleRequestError",
			logger.String("Path", requestedPath),
			logger.Err(err),
		)
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
	}
}

func (a *WebReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestedPath := r.URL.Path
	if matchs := pathRegex.MatchString(r.URL.Path); matchs {
		r.URL.Path = pathRegex.ReplaceAllString(r.URL.Path, "")
	}
	session := a.GetSession()
	token, err := session.Serialize()
	if err != nil {
		logger.Error("ErrSerializingSession", logger.String("session", session.String()))
		return
	}
	cookie := &http.Cookie{
		Name:    a.SecurityConfig.CookieName,
		Value:   string(token),
		Domain:  a.SecurityConfig.CookieDomain,
		Path:    a.SecurityConfig.CookiePath,
		Expires: session.ExpiresAt,
	}
	//http.SetCookie(w, cookie)
	r.AddCookie(cookie)
	//r.Header.Set("Authorization", fmt.Sprintf("%v: %v", a.SecurityConfig.CookieName, privateSession.Token))
	w.Header().Set(fmt.Sprintf("X-%s", a.SecurityConfig.CookieName), string(token))

	//Creates a JWT to proxy the request
	logger.Debug("CookieAuthFoward",
		logger.String(a.SecurityConfig.CookieName, session.ID),
		logger.String("Requested", requestedPath),
		logger.String("Foward", a.ProxyURL.String()+r.URL.Path),
	)
	a.reverseProxy.ServeHTTP(w, r)
}
