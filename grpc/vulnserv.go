package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os/exec"

	"google.golang.org/grpc"
	pb "yourpackage/yourproto"
)

const (
	port        = ":6969"
	defaultPage = "index.html"
)

// server is used to implement chat.ChatServer.
type server struct{}

// SendChat implements chat.ChatServer
func (s *server) SendChat(ctx context.Context, in *pb.ChatMessage) (*pb.ChatMessage, error) {
	// Simulate command injection vulnerability
	cmd := exec.Command("echo", in.Message)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command execution failed: %v", err)
	}
	return &pb.ChatMessage{Message: string(out)}, nil
}

// HandleHTTP handles HTTP requests
func (s *server) HandleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received HTTP request: %s %s", r.Method, r.URL.Path)
	// Simulate XXE vulnerability by parsing XML input
	decoder := xml.NewDecoder(r.Body)
	var msg pb.ChatMessage
	err := decoder.Decode(&msg)
	if err != nil {
		log.Printf("XML parsing failed: %v", err)
	}
	// Simulate CSRF vulnerability by performing a sensitive action without checking the origin
	cmd := exec.Command("echo", msg.Message)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Command execution failed: %v", err)
	}
	log.Printf("Sensitive action executed: %s", out)
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterChatServer(s, &server{})

	// Serve HTTP requests
	http.HandleFunc("/", s.HandleHTTP)
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("failed to serve HTTP: %v", err)
		}
	}()

	log.Printf("Server listening on port %s", port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
