package domain

type TokenRequest struct {
	GrantType string `schema:"grant_type,required"`
	ClientID string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`
	Scope string `schema:"scope"`
}