// vulnlab.go
//
// Build
//   go get github.com/golang-jwt/jwt/v5
//   go get github.com/go-sql-driver/mysql
//   go get github.com/google/uuid
//   go get golang.org/x/crypto/argon2
//
// Run
//   go run vulnlab.go                 # secure mode
//   VULN_MODE=true go run vulnlab.go  # vulnerable mode

package main

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	crand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "yourpackage/yourproto" // replace with your proto import path
)

/* ─── Config ─────────────────────────────────────────────────────────── */

var (
	grpcPort  = env("PORT", ":6969")
	httpPort  = env("HTTP_PORT", ":8080")
	vulnMode  = strings.EqualFold(os.Getenv("VULN_MODE"), "true")
	mysqlDSN  = env("MYSQL_DSN", "root:password@tcp(127.0.0.1:3306)/yourdb")
	allowList = []string{"https://example.com", "https://internal.service"}

	hsSecret   = []byte("secret") // weak HS-256 key in vuln mode
	rsaPrivKey *rsa.PrivateKey    // strong RS-256 key for secure mode
)

func env(k, d string) string { if v := os.Getenv(k); v != "" { return v }; return d }

/* ─── gRPC service ───────────────────────────────────────────────────── */

type chatServer struct{ pb.UnimplementedChatServer }

func (s *chatServer) SendChat(_ context.Context, in *pb.ChatMessage) (*pb.ChatMessage, error) {
	if vulnMode {
		out, _ := exec.Command("sh", "-c", in.Message).CombinedOutput()
		return &pb.ChatMessage{Message: string(out)}, nil
	}
	msg := in.Message
	if len(msg) > 120 { msg = msg[:120] + "…" }
	return &pb.ChatMessage{Message: "echo: " + msg}, nil
}

func (s *chatServer) SQLInjection(_ context.Context, in *pb.SQLInjectionRequest) (*pb.SQLInjectionResponse, error) {
	db, err := sql.Open("mysql", mysqlDSN); if err != nil { return nil, err }; defer db.Close()
	var rows *sql.Rows
	if vulnMode {
		q := fmt.Sprintf("SELECT username,email FROM users WHERE username='%s'", in.Username)
		rows, err = db.Query(q)
	} else {
		stmt, _ := db.Prepare("SELECT username,email FROM users WHERE username=?")
		rows, err = stmt.Query(in.Username)
	}
	if err != nil { return nil, err }; defer rows.Close()

	var resp pb.SQLInjectionResponse
	for rows.Next() {
		var u pb.User
		if err := rows.Scan(&u.Username, &u.Email); err != nil { return nil, err }
		resp.Users = append(resp.Users, &u)
	}
	return &resp, nil
}

/* ─── HTTP handlers ──────────────────────────────────────────────────── */

type httpSrv struct{}

func (httpSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/xml"     && r.Method == http.MethodPost: handleXML(w, r)
	case r.URL.Path == "/fetch":      handleFetch(w, r)
	case r.URL.Path == "/reflect":    handleReflect(w, r)
	case r.URL.Path == "/redirect":   handleRedirect(w, r)
	case r.URL.Path == "/jwt":        issueJWT(w, r)
	case r.URL.Path == "/flag":       protectedFlag(w, r)
	case r.URL.Path == "/upload" && r.Method == http.MethodPost: handleUpload(w, r)
	case r.URL.Path == "/hash":       handleHash(w, r)
	default: http.NotFound(w, r)
	}
}

/* --- XXE + CSRF ------------------------------------------------------ */

func handleXML(w http.ResponseWriter, r *http.Request) {
	if !vulnMode {
		if o := r.Header.Get("Origin"); o != "" && !strings.HasPrefix(o, "http://localhost") {
			http.Error(w, "CSRF blocked", http.StatusForbidden); return
		}
	}
	dec := xml.NewDecoder(r.Body)
	if !vulnMode { dec.Entity = map[string]string{} }

	var msg pb.ChatMessage
	if err := dec.Decode(&msg); err != nil {
		http.Error(w, "bad XML", http.StatusBadRequest); return
	}
	out, _ := exec.Command("echo", msg.Message).CombinedOutput()
	w.Write(out)
}

/* --- SSRF ------------------------------------------------------------ */

func handleFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" { http.Error(w, "missing url", http.StatusBadRequest); return }
	if !vulnMode && !allowed(target) { http.Error(w, "blocked", http.StatusForbidden); return }

	resp, err := http.Get(target); if err != nil { http.Error(w, err.Error(), http.StatusBadGateway); return }
	defer resp.Body.Close(); io.Copy(w, resp.Body)
}

func allowed(u string) bool { for _, p := range allowList { if strings.HasPrefix(u, p) { return true } }; return false }

/* --- Header reflection / XSS ---------------------------------------- */

func handleReflect(w http.ResponseWriter, r *http.Request) {
	payload := r.Header.Get("X-Input")
	if vulnMode { fmt.Fprintf(w, "You said: %s", payload); return }
	fmt.Fprintf(w, "You said: %q", payload)
}

/* --- Open redirect --------------------------------------------------- */

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if vulnMode { http.Redirect(w, r, to, http.StatusFound); return }
	if strings.HasPrefix(to, "/") { http.Redirect(w, r, to, http.StatusFound) }
	else { http.Error(w, "invalid redirect", http.StatusBadRequest) }
}

/* --- File upload / stored-XSS demo ---------------------------------- */

const uploadDir = "./public"

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest); return
	}
	file, hdr, err := r.FormFile("file"); if err != nil { http.Error(w, err.Error(), http.StatusBadRequest); return }
	defer file.Close()
	os.MkdirAll(uploadDir, 0755)

	if vulnMode {
		dst, err := os.Create(filepath.Join(uploadDir, hdr.Filename))
		if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
		defer dst.Close(); io.Copy(dst, file)
		fmt.Fprintf(w, "/files/%s\n", hdr.Filename)
		return
	}

	// secure path: validate mime, random name
	buf := make([]byte, 512); n, _ := file.Read(buf); mime := http.DetectContentType(buf[:n])
	allowed := map[string]bool{"text/plain": true, "image/png": true, "image/jpeg": true, "application/pdf": true}
	if !allowed[mime] { http.Error(w, "type not allowed", http.StatusUnsupportedMediaType); return }
	if _, err := file.Seek(0, io.SeekStart); err != nil { http.Error(w, err.Error(), 500); return }

	name := uuid.New().String() + filepath.Ext(hdr.Filename)
	dst, err := os.Create(filepath.Join(uploadDir, name))
	if err != nil { http.Error(w, err.Error(), 500); return }
	defer dst.Close(); io.Copy(dst, file)
	fmt.Fprintf(w, "/files/%s\n", name)
}

/* --- Hashing demo ---------------------------------------------------- */

func handleHash(w http.ResponseWriter, r *http.Request) {
	pw := r.URL.Query().Get("pw")
	if pw == "" { http.Error(w, "missing pw", http.StatusBadRequest); return }

	if vulnMode {
		sum := md5.Sum([]byte(pw))
		fmt.Fprintf(w, "md5:%x\n", sum)
		return
	}

	// Argon2id with random salt
	salt := make([]byte, 16); crand.Read(salt)
	hash := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 4, 32)
	fmt.Fprintf(w, "argon2:%s:%s\n", hex.EncodeToString(salt), hex.EncodeToString(hash))
}

/* --- JWT issuance & flag -------------------------------------------- */

func issueJWT(w http.ResponseWriter, _ *http.Request) {
	var token string; var err error
	if vulnMode {
		t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "victim", "exp": time.Now().Add(5 * time.Minute).Unix()})
		token, err = t.SignedString(hsSecret)
	} else {
		t := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "user123", "exp": time.Now().Add(5 * time.Minute).Unix()})
		token, err = t.SignedString(rsaPrivKey)
	}
	if err != nil { http.Error(w, err.Error(), 500); return }
	fmt.Fprintln(w, token)
}

func protectedFlag(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" { http.Error(w, "missing token", http.StatusUnauthorized); return }

	keyFn := func(_ *jwt.Token) (interface{}, error) {
		if vulnMode { return hsSecret, nil }
		return &rsaPrivKey.PublicKey, nil
	}
	if _, err := jwt.Parse(bearer, keyFn); err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized); return
	}
	fmt.Fprintln(w, "FLAG{pwned_the_lab}")
}

/* ─── main ───────────────────────────────────────────────────────────── */

func main() {
	if !vulnMode {
		var err error
		rsaPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil { log.Fatalf("RSA keygen: %v", err) }
	}

	// static file server (always on)
	http.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))

	go func() {
		log.Printf("HTTP  %s  (vuln: %v)", httpPort, vulnMode)
		if err := http.ListenAndServe(httpPort, &httpSrv{}); err != nil { log.Fatalf("HTTP: %v", err) }
	}()

	lis, err := net.Listen("tcp", grpcPort); if err != nil { log.Fatalf("gRPC listen: %v", err) }
	gs := grpc.NewServer(); pb.RegisterChatServer(gs, &chatServer{}); reflection.Register(gs)
	log.Printf("gRPC %s  (vuln: %v)", grpcPort, vulnMode)
	if err := gs.Serve(lis); err != nil { log.Fatalf("gRPC: %v", err) }
}
