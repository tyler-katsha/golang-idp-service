package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/schema"
	"github.com/sirupsen/logrus"
	"github.com/tyler-katsha/golang-idp-service/internals/domain"
	"golang.org/x/crypto/bcrypt"
)

var (
	ClientCredentials = "client_credentials"
	AppJSON = "application/json"
	ContentType = "Content-Type"
	ClientID = "client_id"
	AuthFailedUnknownClient = "Authentication failed: unknown client"
	AuthFailedSecretMismatch = "Authentication failed: secret mismatch"
	CacheControl = "Cache-Control"
	NoStore = "no-store"
	FailedToSignJWT = "Failed to sign JWT"
	ErrInvalidRequest = `{"error":"invalid_request"}`
	ErrUnsupportedGrantType = `{"error":"unsupported_grant_type"}`
	ErrServerError = `{"error":"server_error"}`
)

type OAuthHandler struct {
	store domain.ClientStore
	decode *schema.Decoder
	logger *logrus.Logger
	jwtSecret []byte
}

func NewOAuthHandler(store domain.ClientStore, logger *logrus.Logger, secret []byte) *OAuthHandler {
	decode := schema.NewDecoder()
	decode.IgnoreUnknownKeys(true)
	return &OAuthHandler{
		store: store,
		decode: decode,
		logger: logger,
		jwtSecret: secret,
	}
}

func (o *OAuthHandler) IssueToken(w http.ResponseWriter, r *http.Request) {

	if err := r.ParseForm(); err != nil {
		http.Error(w,ErrInvalidRequest,http.StatusBadRequest);
		return
	}

	var req domain.TokenRequest
	if err := o.decode.Decode(&req,r.PostForm); err != nil {
		http.Error(w,ErrInvalidRequest,http.StatusBadRequest)
		return
	}

	if clientID, secretID, ok := r.BasicAuth(); ok {
		req.ClientID = clientID
		req.ClientSecret = secretID
	}

	if req.GrantType != ClientCredentials {
		http.Error(w,ErrUnsupportedGrantType,http.StatusBadRequest)
		return
	}

	client,err := o.store.GetByID(r.Context(),req.ClientID)

	if err != nil {
		o.logger.WithField(ClientID,req.ClientID).Warn(AuthFailedUnknownClient)
		http.Error(w,ErrInvalidRequest, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(req.ClientSecret)); err != nil {
		o.logger.WithField(ClientID, req.ClientID).Warn(AuthFailedSecretMismatch)
		http.Error(w, ErrInvalidRequest, http.StatusUnauthorized)
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"jti":   uuid.NewString(),
		"sub":   client.ClientID,
		"iss":   "https://auth.internal.enterprise",
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
		"scope": client.Scopes,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(o.jwtSecret)
	if err != nil {
		o.logger.WithError(err).Error(FailedToSignJWT)
		http.Error(w, ErrServerError, http.StatusInternalServerError)
		return
	}

	w.Header().Set(ContentType, AppJSON)
	w.Header().Set(CacheControl, NoStore)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": signedToken,
		"token_type":   "Bearer",
		"expires_in":   900,
	})
}