package dto

import "github.com/go-minstack/auth"

type ProfileDto struct {
	Subject string   `json:"subject"`
	Name    string   `json:"name"`
	Roles   []string `json:"roles"`
}

func NewProfileDto(claims *auth.Claims) ProfileDto {
	return ProfileDto{
		Subject: claims.Subject,
		Name:    claims.Name,
		Roles:   claims.Roles,
	}
}
