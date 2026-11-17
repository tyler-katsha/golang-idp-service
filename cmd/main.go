package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sirupsen/logrus"
	"github.com/tyler-katsha/golang-idp-service/internals/domain"

	"github.com/tyler-katsha/golang-idp-service/internals/transport/http/handler"
	"github.com/joho/godotenv"
)

var (
	PATH = "../secrets/.env"
	JWTSECRET = "JWT_SIGNING_SECRET"
)

func main() {

	
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	if err := godotenv.Load(PATH); err != nil {
		logger.Fatalln("No .env file found, fallback to system environment")
	}


	var clientStore domain.ClientStore 
	jwtSecret := []byte(os.Getenv(JWTSECRET))

	oauthHandler := handler.NewOAuthHandler(clientStore, logger, jwtSecret)

	
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(10 * time.Second))

	r.Route("/oauth2", func(r chi.Router) {
		r.Post("/token", oauthHandler.IssueToken)
	})

	r.Use(middleware.LeakyBucketMiddleware(10))

	r.Post("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Token generated successfully"))
	})

	srv := &http.Server{
		Addr:         ":8000",
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("Starting Go IdP Server on port 8000")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Server crashed")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server forced to shutdown")
	}
	logger.Info("Server exited cleanly")
}

func Getenv(key, fallback string) string {
	if val, exists := os.LookupEnv(JWTSECRET); exists {
		return val
	}
	return fallback
}