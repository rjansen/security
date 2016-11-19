package view

import (
	"farm.e-pedion.com/repo/security/model"
)

func ToLoginModel(view Login) model.Login {
	return model.Login{
		Username: view.Username,
		Name:     view.Name,
		Password: view.Password,
		Roles:    view.Roles,
	}
}

func ToLoginView(model model.Login) Login {
	return Login{
		Username: model.Username,
		Name:     model.Name,
		Password: "**-secrect-**",
		Roles:    model.Roles,
	}
}

func ToSessionModel(view Session) model.Session {
	return model.Session{
		ID:       view.Id,
		Username: view.Username,
		Issuer:   view.Issuer,
	}
}

func ToSessionView(model model.Session) Session {
	return Session{
		Id:       model.ID,
		Username: model.Username,
		Issuer:   model.Issuer,
	}
}
