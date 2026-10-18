// https://gist.githubusercontent.com/creack/4c00ee404f2d7bd5983382cc93af5147/raw/66e9641ef1f9b217efeb4dcf04b8cfa662092a81/main.go
//

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

type middleware func(http.Handler) http.Handler
type middlewares []middleware

func (mws middlewares) apply(hdlr http.Handler) http.Handler {
	if len(mws) == 0 {
		return hdlr
	}
	return mws[1:].apply(mws[0](hdlr))
}

func (c *controller) shutdown(ctx context.Context, server *http.Server) context.Context {
	ctx, done := context.WithCancel(ctx)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		defer done()

		<-quit
		signal.Stop(quit)
		close(quit)

		atomic.StoreInt64(&c.healthy, 0)
		server.ErrorLog.Printf("Server is shutting down...\n")

		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			server.ErrorLog.Fatalf("Could not gracefully shutdown the server: %s\n", err)
		}
	}()

	return ctx
}

type controller struct {
	logger        *log.Logger
	nextRequestID func() string
	healthy       int64
}

func main() {
	listenAddr := ":5000"
	if len(os.Args) == 2 {
		listenAddr = os.Args[1]
	}

	logger := log.New(os.Stdout, "http: ", log.LstdFlags)
	logger.Printf("Server is starting...")

	c := &controller{logger: logger, nextRequestID: func() string { return strconv.FormatInt(time.Now().UnixNano(), 36) }}
	router := http.NewServeMux()
	router.HandleFunc("/", c.index)
	router.HandleFunc("/healthz", c.healthz)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      (middlewares{c.tracing, c.logging}).apply(router),
		ErrorLog:     logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}
	ctx := c.shutdown(context.Background(), server)

	logger.Printf("Server is ready to handle requests at %q\n", listenAddr)
	atomic.StoreInt64(&c.healthy, time.Now().UnixNano())

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatalf("Could not listen on %q: %s\n", listenAddr, err)
	}
	<-ctx.Done()
	logger.Printf("Server stopped\n")
}

func (c *controller) index(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	fmt.Fprintf(w, "Hello, World!\n")
}

func (c *controller) healthz(w http.ResponseWriter, req *http.Request) {
	if h := atomic.LoadInt64(&c.healthy); h == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		fmt.Fprintf(w, "uptime: %s\n", time.Since(time.Unix(0, h)))
	}
}

func (c *controller) logging(hdlr http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		defer func(start time.Time) {
			requestID := w.Header().Get("X-Request-Id")
			if requestID == "" {
				requestID = "unknown"
			}
			c.logger.Println(requestID, req.Method, req.URL.Path, req.RemoteAddr, req.UserAgent(), time.Since(start))
		}(time.Now())
		hdlr.ServeHTTP(w, req)
	})
}

func (c *controller) tracing(hdlr http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestID := req.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = c.nextRequestID()
		}
		w.Header().Set("X-Request-Id", requestID)
		hdlr.ServeHTTP(w, req)
	})
}

//
//
// https://gist.github.com/peterhellberg/e36274f213f7a2e2b89a3d837fbafbe1
// main_test.go
//
//

var (
	_ http.Handler = http.HandlerFunc((&controller{}).index)
	_ http.Handler = http.HandlerFunc((&controller{}).healthz)
	_ middleware   = (&controller{}).logging
	_ middleware   = (&controller{}).tracing
)

//
//




 A pretty minimal HTTP server example in Go
minimal-server.go
package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	logger := log.New(os.Stdout, "", 0)

	hs := setup(logger)

	logger.Printf("Listening on http://0.0.0.0%s\n", hs.Addr)

	hs.ListenAndServe()
}

func setup(logger *log.Logger) *http.Server {
	return &http.Server{
		Addr:         getAddr(),
		Handler:      newServer(logWith(logger)),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func getAddr() string {
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}

	return ":8383"
}

func newServer(options ...Option) *Server {
	s := &Server{logger: log.New(ioutil.Discard, "", 0)}

	for _, o := range options {
		o(s)
	}

	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/", s.index)

	return s
}

type Option func(*Server)

func logWith(logger *log.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

type Server struct {
	mux    *http.ServeMux
	logger *log.Logger
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	s.log("%s %s", r.Method, r.URL.Path)

	s.mux.ServeHTTP(w, r)
}

func (s *Server) log(format string, v ...interface{}) {
	s.logger.Printf(format+"\n", v...)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, world!"))
}
@peterhellberg
Author
peterhellberg commented Apr 28, 2020 •

Example with more than one package: https://play.golang.org/p/ukMvKCQE4kh

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"play.ground/api"
)

func main() {
	logger := log.New(os.Stdout, "", 0)

	hs := newHTTPServer(getAddr(), api.NewHandler(api.LogWith(logger)))

	// Just for the playground example (in the real code you’d call ListenAndServe)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/other", nil)

	hs.Handler.ServeHTTP(w, r)

	fmt.Println(w.Body.String())
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

func getAddr() string {
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}

	return ":8383"
}
-- go.mod --
module play.ground
-- api/handler.go --
package api

import (
	"encoding/json"
	"net/http"
)

type Option func(*Handler)

type Logger interface {
	Printf(format string, v ...interface{})
}

func LogWith(logger Logger) Option {
	return func(h *Handler) {
		h.logger = logger
	}
}

type Handler struct {
	logger Logger
	mux    *http.ServeMux
}

func NewHandler(options ...Option) *Handler {
	h := &Handler{}

	for _, o := range options {
		o(h)
	}

	h.mux = http.NewServeMux()
	h.mux.HandleFunc("/", h.index)
	h.mux.HandleFunc("/other", h.other)

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.log("%s %s", r.Method, r.URL.Path)

	h.mux.ServeHTTP(w, r)
}

func (h *Handler) log(format string, v ...interface{}) {
	if h.logger != nil {
		h.logger.Printf(format+"\n", v...)
	}
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Write([]byte("Hello, world!"))
}

func (h *Handler) other(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]interface{}{
		"other": 123,
	})
}

@peterhellberg
Author
peterhellberg commented Jun 26, 2020 •

Example with a domain package and a service: https://play.golang.org/p/Yft7Ftg-nFL

package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"play.ground/api"
	"play.ground/app"
	"play.ground/services/userservice"
)

func main() {
	logger := log.New(os.Stdout, "", 0)

	us := userservice.New(
		&app.User{ID: "1", Name: "Peter Hellberg"},
		&app.User{ID: "2", Name: "Sumukha Pk"},
	)

	h := api.NewHandler(us, api.LogWith(logger))

	// Following just for the playground example (in the real code you’d call ListenAndServe)

	getRequest := func(handler http.Handler, path string) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)

		handler.ServeHTTP(w, r)

		fmt.Println(w.Body.String())
	}

	getRequest(h, "/")
	getRequest(h, "/users")
	getRequest(h, "/users/1")
	getRequest(h, "/users/3")
}
-- go.mod --
module play.ground
-- api/handler.go --
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"play.ground/app"
)

type Option func(*Handler)

func LogWith(logger app.Logger) Option {
	return func(h *Handler) {
		h.logger = logger
	}
}

type Handler struct {
	app.UserService

	logger app.Logger
	mux    *http.ServeMux
}

func NewHandler(us app.UserService, options ...Option) *Handler {
	h := &Handler{UserService: us}

	for _, o := range options {
		o(h)
	}

	h.mux = http.NewServeMux()
	h.mux.HandleFunc("/", h.index)
	h.mux.HandleFunc("/users", h.users)
	h.mux.HandleFunc("/users/", h.user)

	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.log("%s %s", r.Method, r.URL.Path)

	h.mux.ServeHTTP(w, r)
}

func (h *Handler) log(format string, v ...interface{}) {
	if h.logger != nil {
		h.logger.Printf(format+"\n", v...)
	}
}

func (h *Handler) index(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	w.Write([]byte("Hello, world!\n"))
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(h.AllUsers())
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/users/")

	u, err := h.GetUser(id)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(u)
}
-- app/app.go --
package app

import "fmt"

var ErrUserNotFound = fmt.Errorf("user not found")

type Logger interface {
	Printf(format string, v ...interface{})
}

type User struct {
	ID   string
	Name string
}

type UserService interface {
	AllUsers() []*User
	GetUser(id string) (*User, error)
}
-- services/userservice/userservice.go --
package userservice

import "play.ground/app"

type Service struct {
	data map[string]*app.User
}

func New(users ...*app.User) *Service {
	s := &Service{data: map[string]*app.User{}}
	for _, u := range users {
		s.data[u.ID] = u
	}

	return s
}

func (s *Service) AllUsers() []*app.User {
	users := []*app.User{}

	for _, user := range s.data {
		users = append(users, user)
	}

	return users
}

func (s *Service) GetUser(id string) (*app.User, error) {
	if u, ok := s.data[id]; ok {
		return u, nil
	}

	return nil, app.ErrUserNotFound
}

//
//
