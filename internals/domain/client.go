package domain

import "context"

type OAuthClient struct {
	ClientID string
	ClientSecret string
	Scopes []string
}


type ClientStore interface {
	GetByID(ctx context.Context, clientID string) (*OAuthClient, error)
}