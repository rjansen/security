package proxy

import (
    "fmt"
    "log"
    "regexp"
    "net/url"
    "net/http"
    "net/http/httputil"
    "farm.e-pedion.com/repo/security/identity"
)

var (
    pathRegex, _ = regexp.Compile("\\/web|\\/api")
)

func NewApiReverseProxy(targetURL *url.URL) http.Handler {
    return identity.NewCookieAuthenticatedHandler(&ApiReverseProxy{ProxyUrl: targetURL, reverseProxy: httputil.NewSingleHostReverseProxy(targetURL)})
}

type ApiReverseProxy struct {
    ProxyUrl *url.URL
    session *identity.Session
    reverseProxy *httputil.ReverseProxy
}

func (a *ApiReverseProxy) SetSession(session *identity.Session) {
    a.session = session
}

func (a *ApiReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    requestedPath := r.URL.Path
    if matchs := pathRegex.MatchString(r.URL.Path); matchs {
        r.URL.Path = pathRegex.ReplaceAllString(r.URL.Path, "");
    }
    //r.SetBasicAuth(a.session.Username, a.session.ID)
    r.Header.Set("Authorization", fmt.Sprintf("FFM_ID %v", a.session.ID))
    log.Printf("BasicAuthFoward: FFM_ID[%v] Requested[%v] Foward[%v%v]", a.session.ID, requestedPath, a.ProxyUrl, r.URL.Path);
    a.reverseProxy.ServeHTTP(w, r)
}

func NewWebReverseProxy(targetURL *url.URL) http.Handler {
    return identity.NewCookieAuthenticatedHandler(&WebReverseProxy{ProxyUrl: targetURL, reverseProxy: httputil.NewSingleHostReverseProxy(targetURL)})
}

type WebReverseProxy struct {
    ProxyUrl *url.URL
    session *identity.Session
    reverseProxy *httputil.ReverseProxy
}

func (a *WebReverseProxy) SetSession(session *identity.Session) {
    a.session = session
}

func (a *WebReverseProxy)  ServeHTTP(w http.ResponseWriter, r *http.Request) {
    requestedPath := r.URL.Path
    if matchs := pathRegex.MatchString(r.URL.Path); matchs {
        r.URL.Path = pathRegex.ReplaceAllString(r.URL.Path, "");
    }
    log.Printf("CookieAuthFoward: FFM_ID[%v] Requested[%v] Foward[%v%v]", a.session.ID, requestedPath, a.ProxyUrl, r.URL.Path)
    a.reverseProxy.ServeHTTP(w, r)
}

