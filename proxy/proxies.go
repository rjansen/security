package proxy

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"

	"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/security/handler"
)

var (
	//Create a config way to strip paths while proxy request
	pathRegex, _ = regexp.Compile("\\/web|\\/api")
)

func NewApiReverseProxy(targetURL *url.URL) http.Handler {
	return handler.NewSessionCookieHandler(
		&ApiReverseProxy{
			SecurityConfig: config.BindSecurityConfiguration(),
			ProxyURL:       targetURL,
			reverseProxy:   httputil.NewSingleHostReverseProxy(targetURL),
		})
}

type ApiReverseProxy struct {
	handler.AuthenticatedHandler
	*config.SecurityConfig
	ProxyURL     *url.URL
	reverseProxy *httputil.ReverseProxy
}

func (a *ApiReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestedPath := r.URL.Path
	if matchs := pathRegex.MatchString(r.URL.Path); matchs {
		r.URL.Path = pathRegex.ReplaceAllString(r.URL.Path, "")
	}
	//Creates a JWT to proxy the request
	privateSession := a.GetSession().PrivateSession
	if err := privateSession.Serialize(); err != nil {
        return
    }
	//r.SetBasicAuth(a.session.Username, a.session.ID)
	r.Header.Set("Authorization", fmt.Sprintf("%v: %v", a.SecurityConfig.CookieName, string(privateSession.Token)))
	log.Printf("HeaderAuthorizationFoward[%v=%v Requested=%v Foward=%v%v]", a.SecurityConfig.CookieName, privateSession.ID, requestedPath, a.ProxyURL, r.URL.Path)
	a.reverseProxy.ServeHTTP(w, r)
}

func NewWebReverseProxy(targetURL *url.URL) http.Handler {
	return handler.NewSessionCookieHandler(
		&WebReverseProxy{
			SecurityConfig: config.BindSecurityConfiguration(),
			ProxyURL:       targetURL,
			reverseProxy:   httputil.NewSingleHostReverseProxy(targetURL),
		})
}

type WebReverseProxy struct {
	handler.AuthenticatedHandler
	*config.SecurityConfig
	ProxyURL     *url.URL
	reverseProxy *httputil.ReverseProxy
}

func (a *WebReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestedPath := r.URL.Path
	if matchs := pathRegex.MatchString(r.URL.Path); matchs {
		r.URL.Path = pathRegex.ReplaceAllString(r.URL.Path, "")
	}
	privateSession := a.GetSession().PrivateSession
	if err := privateSession.Serialize(); err != nil {
		return
	}
	cookie := &http.Cookie{
		Name:    a.SecurityConfig.CookieName,
		Value:   string(privateSession.Token),
		Domain:  a.SecurityConfig.CookieDomain,
		Path:    a.SecurityConfig.CookiePath,
		Expires: privateSession.Expires,
	}
	//http.SetCookie(w, cookie)
	r.AddCookie(cookie)
    //r.Header.Set("Authorization", fmt.Sprintf("%v: %v", a.SecurityConfig.CookieName, privateSession.Token))
	w.Header().Set(fmt.Sprintf("X-%v", a.SecurityConfig.CookieName), string(privateSession.Token))

	//Creates a JWT to proxy the request
	log.Printf("CookieAuthFoward[%v=%v Requested=%v Foward=%v%v]", a.SecurityConfig.CookieName, privateSession.ID, requestedPath, a.ProxyURL, r.URL.Path)
	a.reverseProxy.ServeHTTP(w, r)
}
