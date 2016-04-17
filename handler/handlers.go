package handler

import (
    "log"
    "time"
    "regexp"
    "strings"
    "net/http"
    "html/template"
    "farm.e-pedion.com/repo/security/identity"
)

func NewLoginHandler() *LoginHandler {
    return &LoginHandler{}
}

type LoginPageData struct {
    //Error, Warning, Info
    MessageType string
    Message string
    LoginUserData LoginUserData
}

type LoginUserData struct {
    RemmenberUser bool
    Username string
    ImageURL string
}

type LoginHandler struct {
}

func (l *LoginHandler) renderLoginPage(w http.ResponseWriter, parameters *LoginPageData) {
    t, err := template.ParseFiles("html/login.html")
    if err != nil {
        log.Printf("LoginHandler.PageParserError: Page[html/login.html] Params[%v] Error[%v]", parameters, err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
    } else {
        t.Execute(w, parameters)
    }
}

func (l *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    log.Printf("LoginHandler.ServeHTTP: Method[%v] URL[%v] HOST[%v]", r.Method, r.URL, r.Host)
   if r.Method == "GET" {
       parameters := &LoginPageData{LoginUserData: LoginUserData{RemmenberUser: true}}
       l.renderLoginPage(w, parameters)
       //log.Printf("LoginHandler.GetAuthPage: Method[GET] URL[%v] HOST[%v] Headers[%q]", r.URL, r.Host, r.Header)
       log.Printf("LoginHandler.GetAuthPage: Method[GET] URL[%v] HOST[%v]", r.URL, r.Host)
    } else if r.Method == "POST" {
        resultContentNegotiator := func(err error) {
            apiAcceptRegex := "json|plain"
            accept := r.Header.Get("Accept")
            log.Printf("LoginHandler.ContentNegotiator: ApiAcceptRegex[%v] Accept[%v]", apiAcceptRegex, accept)
            if matches, _ := regexp.MatchString(apiAcceptRegex, accept); matches {
                if err == nil {
                    w.WriteHeader(http.StatusOK)
                } else {
                    w.WriteHeader(http.StatusUnauthorized)
                }
            } else {
                if err == nil {
                    http.Redirect(w, r, "https://" + r.Header.Get("X-Forwarded-Host") + "/ffm/web/ffm.html", http.StatusFound)
                } else {
                    parameters := &LoginPageData{MessageType: "Error", Message: "Invalid credentials", LoginUserData: LoginUserData{RemmenberUser: true}} 
                    l.renderLoginPage(w, parameters)
                }
            }
         }
        //log.Printf("LoginHandler.CreatingSession: Method[POST] URL[%v] HOST[%v] Headers[%q]", r.URL, r.Host, r.Header)
        log.Printf("LoginHandler.CreatingSession: Method[POST] URL[%v] HOST[%v]", r.URL, r.Host)
        //Dummy credentials
        username := r.FormValue("epedion_username")
        password := r.FormValue("epedion_password")
        login, err := identity.ReadLogin(username)
        if err != nil {
            log.Printf("LoginHandler.ReadUserError: Username[%v] Error[%v]", username, err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        if err := login.CheckCredentials(password); err != nil {
            log.Printf("LoginHandler.InvalidCredentials: Username[%v] Password[%v] Error[%v]", username, password, err)
            resultContentNegotiator(err)
            return
        }
        session := &identity.Session{Username: login.Username, Roles: login.Roles, TTL: 1}
        if err = session.Set(); err != nil {
            log.Printf("LoginHandler.SaveSessionError: Username[%v] Error[%v]", username, err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        log.Printf("LoginHandler.SessionExpires: SessionId[%v] Now[%v] Expires[%v]", session.ID, time.Now(), session.Expires)
        cookie := &http.Cookie{Name: identity.CookieID, Value: session.ID, Domain: "darkside.e-pedion.com", Path: "/", Expires: session.Expires}
        http.SetCookie(w, cookie)
        r.AddCookie(cookie)
        w.Header().Set("X-EPEDION_ID", session.ID)
        log.Printf("LoginHandler.CreatedSession: SessionId[%v] Cookie[%v] URL[%v]", session.ID, cookie, r.URL)
        resultContentNegotiator(nil)
    }
}

func NewLogoutHandler() http.Handler {
    return identity.NewCookieAuthenticatedHandler(&LogoutHandler{})
}

type LogoutHandler struct {
    session *identity.Session
}

func (l *LogoutHandler) SetSession(session *identity.Session) {
    l.session = session
}

func (l *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    cookie, err := r.Cookie(identity.CookieID)
    if err == nil {
        log.Printf("LogoutHandler.SessionIdFound: %v=%v", identity.CookieID, cookie.Value)
        nowTime := time.Now()
        expiresTime := nowTime.AddDate(0, 0, -1)
        log.Printf("LogoutHandler.CookieExpires: Now[%v] Expires[%v]", nowTime, expiresTime)
        cookieExpired := &http.Cookie{Name: identity.CookieID, Domain: "darkside.e-pedion.com", Path: "/", Expires: expiresTime}
        http.SetCookie(w, cookieExpired)
        if matches, _ := regexp.MatchString("json|plain", r.Header.Get("Accept")); matches {
            w.WriteHeader(http.StatusOK)
        } else {
            http.Redirect(w, r, "https://" + r.Header.Get("X-Forwarded-Host") + "/ffm/auth/login/", http.StatusFound)
        }
    } else {
        log.Printf("LogoutHandler.SessionIdNotFound: URL[%v]", r.URL.Path)
        w.WriteHeader(http.StatusNotFound)
    }
}

func NewSessionHandler() http.Handler {
    return identity.NewCookieAuthenticatedHandler(&SessionHandler{})
}

type SessionHandler struct {
    session *identity.Session
}

func (h *SessionHandler) SetSession(session *identity.Session) {
    h.session = session
}

func (h *SessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        urlPathParameters := strings.Split(r.URL.Path, "/")
        log.Printf("SessionHandler.Get: URL[%q] PathParameters[%q] JobId[%v]!", r.URL.Path, urlPathParameters, urlPathParameters[3])

        jsonData, err := h.session.Marshal()
        if err != nil {
            log.Printf("SessionHandler.WriteResponseError: SessionId[%v] Error[%v]", h.session.ID, err)
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }

        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        bytesWritten, err := w.Write(jsonData)
        if err != nil {
            log.Printf("SessionHandler.WriteResponseError: SessionId[%v] Error[%v]", h.session.ID, err)
        } else {
            log.Printf("SessionHandler.ResponseWritten: SessionId[%v] Bytes[%v]", h.session.ID, bytesWritten)
        }
    }
}

