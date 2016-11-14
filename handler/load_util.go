package handler

import (
	"context"
	//"fmt"
	//"net/http"
	//"regexp"
	//"strings"
	//"time"

	//"farm.e-pedion.com/repo/config"
	"farm.e-pedion.com/repo/context/fast"
	"farm.e-pedion.com/repo/context/media/json"
	"farm.e-pedion.com/repo/logger"
	"farm.e-pedion.com/repo/persistence"
	data "farm.e-pedion.com/repo/security/model"
	"farm.e-pedion.com/repo/security/view"

	//"farm.e-pedion.com/repo/security/asset"
	"github.com/valyala/fasthttp"
)

func NewLoadTestHandler() fast.HTTPHandlerFunc {
	handler := &LoadTestHandler{
		Get:  fast.Log(fast.Error(LoadGetTestHandler)),
		Post: fast.Log(fast.Error(LoadPostTestHandler)),
	}
	return handler.HandleRequest
}

//LoadTestHandler is the handler for load test purposes
type LoadTestHandler struct {
	Get  fast.HTTPHandlerFunc
	Post fast.HTTPHandlerFunc
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
		return fast.Status(fc, fasthttp.StatusMethodNotAllowed)
	}
}

//LoadGetTestHandler is the function to handle the find load test
func LoadGetTestHandler(c context.Context, fc *fasthttp.RequestCtx) error {
	if !fc.IsGet() {
		return fast.Status(fc, fasthttp.StatusMethodNotAllowed)
	}
	identifier := string(fc.URI().LastPathSegment())
	logger.Info("LoadGetTestHandler.Request",
		logger.Bytes("Method", fc.Method()),
		logger.String("URI", fc.URI().String()),
		logger.String("query", identifier),
	)

	login := data.Login{
		Username: identifier,
	}
	if err := persistence.Execute(login.Read); err != nil {
		logger.Error("LoadGetTestHandler.ReadLoginError",
			logger.String("Username", identifier),
			logger.Err(err),
		)
		if err == data.NotFoundErr {
			return fast.Status(fc, fasthttp.StatusNotFound)
		}
		return fast.Err(fc, err)
	}

	return fast.JSON(fc, fasthttp.StatusOK, view.ToLoginView(login))
}

//LoadPostTestHandler is the function to handle the post load test
func LoadPostTestHandler(container context.Context, fc *fasthttp.RequestCtx) error {
	if !fc.IsPost() && fc.IsPut() {
		return fast.Status(fc, fasthttp.StatusMethodNotAllowed)
	}
	logger.Info("LoadPostTestHandler.Request",
		logger.Bytes("Method", fc.Method()),
		logger.String("URI", fc.URI().String()),
		logger.Int("bodyLen", len(fc.PostBody())),
	)

	var loginView view.Login
	// if err := fast.ReadJSON(fc, &loginView); err != nil {

	// }
	// if err := fast.ReadProtoBuf(fc, &loginView); err != nil {

	// }
	// if err := fast.ReadByContentType(fc, &loginView); err != nil {

	// }
	if err := json.UnmarshalBytes(fc.PostBody(), &loginView); err != nil {
		logger.Error("handler.LoadPostTestHandler.ReadRequestErr",
			logger.Bytes("Body", fc.PostBody()),
			logger.Err(err),
		)
		return fast.Err(fc, err)
	}

	loginView.Password = "**-secret-**"

	// login := view.ToLoginModel(loginView)
	// if err := login.Write(); err != nil {
	// 	logger.Errorf("ReadLoginError[Username=%v Message='%v']", username, err)
	// 	fc.Error(err.Error(), fasthttp.StatusInternalServerError)
	// 	return
	// }
	// return fast.JSON(fc, fasthttp.StatusCreated, view.ToLoginView(login))

	return fast.JSON(fc, fasthttp.StatusCreated, loginView)
}
