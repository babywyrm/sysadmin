package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/gorilla/mux"
)

// Configuration settings.
const (
	address       = ":8080"
	readTimeout   = 10 * time.Second
	writeTimeout  = 10 * time.Second
	shutdownTime  = 10 * time.Second
)

// initLogger creates a new Zap logger in development mode with custom settings.
func initLogger() (*zap.Logger, error) {
	cfg := zap.NewDevelopmentConfig()
	// Customize output format.
	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.LevelKey = "level"
	cfg.EncoderConfig.MessageKey = "msg"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return cfg.Build()
}

// helloHandler responds with a greeting based on the "name" query parameter.
func helloHandler(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			name = "Guest"
		}
		logger.Info("Processing request", zap.String("handler", "helloHandler"), zap.String("name", name))
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "Hello, %s\n", name)
	}
}

// healthHandler provides a simple health check endpoint.
func healthHandler(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Health check passed", zap.String("handler", "healthHandler"))
		w.WriteHeader(http.StatusOK)
	}
}

// readinessHandler indicates that the service is ready to accept traffic.
func readinessHandler(logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Readiness check passed", zap.String("handler", "readinessHandler"))
		w.WriteHeader(http.StatusOK)
	}
}

// loggingMiddleware logs incoming requests and their duration.
func loggingMiddleware(logger *zap.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			logger.Info("Incoming request",
				zap.String("method", r.Method),
				zap.String("url", r.RequestURI),
				zap.String("remote_addr", r.RemoteAddr))
			next.ServeHTTP(w, r)
			duration := time.Since(start)
			logger.Info("Completed request",
				zap.String("method", r.Method),
				zap.String("url", r.RequestURI),
				zap.Duration("duration", duration))
		})
	}
}

// newRouter initializes the router, applies middleware, and registers routes.
func newRouter(logger *zap.Logger) *mux.Router {
	router := mux.NewRouter()
	router.Use(loggingMiddleware(logger))
	router.HandleFunc("/", helloHandler(logger)).Methods(http.MethodGet)
	router.HandleFunc("/health", healthHandler(logger)).Methods(http.MethodGet)
	router.HandleFunc("/readiness", readinessHandler(logger)).Methods(http.MethodGet)
	return router
}

// startServer starts the HTTP server in a separate goroutine.
func startServer(srv *http.Server, logger *zap.Logger) {
	logger.Info("Starting HTTP server", zap.String("address", srv.Addr))
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server ListenAndServe failed", zap.Error(err))
		}
	}()
}

// gracefulShutdown waits for OS signals and gracefully shuts down the server.
func gracefulShutdown(srv *http.Server, logger *zap.Logger) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	sig := <-stop
	logger.Info("Received shutdown signal", zap.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTime)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Error during server shutdown", zap.Error(err))
	} else {
		logger.Info("Server shutdown gracefully")
	}
}

func main() {
	// Initialize the structured logger.
	logger, err := initLogger()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer logger.Sync() // Flush any buffered log entries.

	// Create a new router with handlers and middleware.
	router := newRouter(logger)

	// Create the HTTP server.
	srv := &http.Server{
		Handler:      router,
		Addr:         address,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	// Start the server.
	startServer(srv, logger)

	// Wait for shutdown signal and then gracefully stop the server.
	gracefulShutdown(srv, logger)
}

//
//
