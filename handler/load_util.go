package handler

import (
	"context"
	//"fmt"
	//"net/http"
	//"regexp"
	//"strings"
	//"time"

	//"farm.e-pedion.com/repo/config"
	ctxFast "farm.e-pedion.com/repo/context/fasthttp"
	"farm.e-pedion.com/repo/context/media"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/security/client/cassandra"
	"farm.e-pedion.com/repo/security/data"

	//"farm.e-pedion.com/repo/security/asset"
	"github.com/valyala/fasthttp"
)

func WithClient(handler ctxFast.HTTPHandlerFunc) ctxFast.HTTPHandlerFunc {
	return func(c context.Context, fc *fasthttp.RequestCtx) error {
		ctxClient := cassandra.SetClient(c)
		return handler(ctxClient, fc)
	}
}

func NewLoadTestHandler() ctxFast.HTTPHandlerFunc {
	handler := &LoadTestHandler{
		Get:  ctxFast.Log(ctxFast.Error(WithClient(LoadGetTestHandler))),
		Post: ctxFast.Log(ctxFast.Error(WithClient(LoadPostTestHandler))),
	}
	return handler.HandleRequest
}

//LoadTestHandler is the handler for load test purposes
type LoadTestHandler struct {
	Get  ctxFast.HTTPHandlerFunc
	Post ctxFast.HTTPHandlerFunc
}

//HandleRequest is the load test router
func (h LoadTestHandler) HandleRequest(c context.Context, fc *fasthttp.RequestCtx) error {
	switch {
	case fc.IsGet():
		return h.Get(c, fc)
	case fc.IsPost(), fc.IsPut():
		return h.Post(c, fc)
	//case fc.IsDelete():
	//	loadTestHandler.Delete.HandleRequest(fc)
	default:
		logger.Info("LoadGetTestHandler.Request",
			logger.Bytes("Method", fc.Method()),
			logger.String("URI", fc.URI().String()),
			logger.String("message", "405 - MethodNotAllowed"),
		)
		return ctxFast.Status(fc, fasthttp.StatusMethodNotAllowed)
	}
}

//LoadGetTestHandler is the function to handle the find load test
func LoadGetTestHandler(c context.Context, fc *fasthttp.RequestCtx) error {
	if !fc.IsGet() {
		return ctxFast.Status(fc, fasthttp.StatusMethodNotAllowed)
	}
	identifier := string(fc.URI().LastPathSegment())
	logger.Info("LoadGetTestHandler.Request",
		logger.Bytes("Method", fc.Method()),
		logger.String("URI", fc.URI().String()),
		logger.String("query", identifier),
	)

	client, getClientErr := cassandra.GetClient(c)
	if getClientErr != nil {
		logger.Error("LoadGetTestHandler.GetClientNotFound",
			logger.String("query", identifier),
			logger.Err(getClientErr),
		)
		return ctxFast.Err(fc, getClientErr)
	}

	login := data.Login{
		Client:   client,
		Username: identifier,
		Name:     "Load Get TestHandler das Couves",
		Password: "dummypwd",
		Roles:    []string{"role1", "role2", "role3", "roleN"},
	}

	if err := login.Read(); err != nil {
		logger.Error("LoadGetTestHandler.ReadLoginError",
			logger.String("Username", identifier),
			logger.Err(err),
		)
		if err == data.NotFoundErr {
			return ctxFast.Status(fc, fasthttp.StatusNotFound)
		}
		return ctxFast.Err(fc, err)
	}

	return ctxFast.JSON(fc, fasthttp.StatusOK, login)
}

//LoadPostTestHandler is the function to handle the post load test
func LoadPostTestHandler(container context.Context, fc *fasthttp.RequestCtx) error {
	if !fc.IsPost() && fc.IsPut() {
		return ctxFast.Status(fc, fasthttp.StatusMethodNotAllowed)
	}
	logger.Info("LoadPostTestHandler.Request",
		logger.Bytes("Method", fc.Method()),
		logger.String("URI", fc.URI().String()),
		logger.Int("bodyLen", len(fc.PostBody())),
	)
	var login data.Login
	if err := media.FromJSONBytes(fc.PostBody(), &login); err != nil {
		logger.Error("handler.LoadPostTestHandler.ReadRequestErr",
			logger.Bytes("Body", fc.PostBody()),
			logger.Err(err),
		)
		return ctxFast.Err(fc, err)
	}
	login.Password = "dummypwd"

	// if err := login.Write(); err != nil {
	// 	logger.Errorf("ReadLoginError[Username=%v Message='%v']", username, err)
	// 	fc.Error(err.Error(), fasthttp.StatusInternalServerError)
	// 	return
	// }

	return ctxFast.JSON(fc, fasthttp.StatusCreated, login)
}
