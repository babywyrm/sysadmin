// go run main.go
// VULN_MODE=true go run main.go     # intentionally insecure
// PORT=9000 go run main.go          # override gRPC port

package main

import (
	"context"
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "yourpackage/yourproto" // ← replace with real import path
)

/* ------------------------------------------------------------------- */
/* 1. Global configuration                                             */
/* ------------------------------------------------------------------- */

var (
	grpcPort   = getEnv("PORT", ":6969")
	httpPort   = getEnv("HTTP_PORT", ":8080")
	vulnMode   = strings.EqualFold(os.Getenv("VULN_MODE"), "true")
	mysqlDSN   = getEnv("MYSQL_DSN", "root:password@tcp(127.0.0.1:3306)/yourdb")
	apWhitelist = []string{"https://example.com", "https://internal.service"} // secure SSRF allow-list
)

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

/* ------------------------------------------------------------------- */
/* 2. gRPC service implementation                                      */
/* ------------------------------------------------------------------- */

type server struct {
	pb.UnimplementedChatServer
}

/* ---------- Chat ---------- */

func (s *server) SendChat(ctx context.Context, in *pb.ChatMessage) (*pb.ChatMessage, error) {
	log.Printf("SendChat called: %q", in.Message)

	if vulnMode {
		// *** Vulnerable: passes user data straight to the shell ***
		cmd := exec.Command("sh", "-c", in.Message)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("exec failed: %v", err)
		}
		return &pb.ChatMessage{Message: string(out)}, nil
	}

	// Secure: just echo back, with length cap
	const maxLen = 100
	msg := in.Message
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "…"
	}
	return &pb.ChatMessage{Message: fmt.Sprintf("echo: %s", msg)}, nil
}

/* ---------- SQL Injection demo ---------- */

func (s *server) SQLInjection(ctx context.Context, in *pb.SQLInjectionRequest) (*pb.SQLInjectionResponse, error) {

	db, err := sql.Open("mysql", mysqlDSN)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var rows *sql.Rows
	if vulnMode {
		// *** Vulnerable: string-concat query ***
		query := fmt.Sprintf("SELECT username,email FROM users WHERE username='%s'", in.Username)
		rows, err = db.Query(query)
	} else {
		// Secure: prepared statement
		stmt, err := db.Prepare("SELECT username,email FROM users WHERE username=?")
		if err != nil {
			return nil, err
		}
		rows, err = stmt.Query(in.Username)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var resp pb.SQLInjectionResponse
	for rows.Next() {
		var u pb.User
		if err := rows.Scan(&u.Username, &u.Email); err != nil {
			return nil, err
		}
		resp.Users = append(resp.Users, &u)
	}
	return &resp, nil
}

/* ------------------------------------------------------------------- */
/* 3. HTTP handlers                                                    */
/* ------------------------------------------------------------------- */

func (s *server) HandleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)
	switch {
	case r.URL.Path == "/xml":
		s.handleXML(w, r)
	case r.URL.Path == "/fetch":
		s.handleFetch(w, r)
	default:
		http.NotFound(w, r)
	}
}

/* ---------- XXE + CSRF demo ---------- */

func (s *server) handleXML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST please", http.StatusMethodNotAllowed)
		return
	}

	if !vulnMode {
		// Simple CSRF mitigation: check Origin
		if o := r.Header.Get("Origin"); o != "" && !strings.HasPrefix(o, "http://localhost") {
			http.Error(w, "CSRF blocked", http.StatusForbidden)
			return
		}
	}

	dec := xml.NewDecoder(r.Body)
	if !vulnMode {
		// Secure: disable external entity resolution
		dec.Entity = map[string]string{}
	}

	var msg pb.ChatMessage
	if err := dec.Decode(&msg); err != nil {
		http.Error(w, "bad XML", http.StatusBadRequest)
		return
	}

	// Re-use command sink
	out, _ := exec.Command("echo", msg.Message).CombinedOutput()
	w.Write(out)
}

/* ---------- SSRF demo ---------- */

func (s *server) handleFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "missing url param", http.StatusBadRequest)
		return
	}
	if !vulnMode && !isAllowed(target) {
		http.Error(w, "blocked by allow-list", http.StatusForbidden)
		return
	}

	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	io.Copy(w, resp.Body)
}

func isAllowed(url string) bool {
	for _, p := range apWhitelist {
		if strings.HasPrefix(url, p) {
			return true
		}
	}
	return false
}

/* ------------------------------------------------------------------- */
/* 4. main: run gRPC + HTTP                                            */
/* ------------------------------------------------------------------- */

func main() {

	lis, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("gRPC listen: %v", err)
	}
	grpcSrv := grpc.NewServer()
	pb.RegisterChatServer(grpcSrv, &server{})
	reflection.Register(grpcSrv) // grpcurl-friendly

	// HTTP mux
	srv := &server{}
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", srv.HandleHTTP)

	// Run HTTP server
	go func() {
		log.Printf("HTTP  listening on %s (vuln mode: %v)", httpPort, vulnMode)
		if err := http.ListenAndServe(httpPort, httpMux); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	// Run gRPC server
	log.Printf("gRPC listening on %s (vuln mode: %v)", grpcPort, vulnMode)
	if err := grpcSrv.Serve(lis); err != nil {
		log.Fatalf("grpc: %v", err)
	}
}
