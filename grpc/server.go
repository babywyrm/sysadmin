package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ChatbotServer implements the chatbot gRPC service
type ChatbotServer struct{}

// SendMessage implements the SendMessage RPC method
func (s *ChatbotServer) SendMessage(ctx context.Context, req *MessageRequest) (*MessageResponse, error) {
	// Verify JWT token from client metadata
	if err := verifyJWT(ctx); err != nil {
		return nil, err
	}

	// Process client message and generate response
	response := generateResponse(req.GetMessage())

	return &MessageResponse{Response: response}, nil
}

// verifyJWT verifies the JWT token from the client metadata
func verifyJWT(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "metadata not found")
	}

	// Extract JWT token from metadata
	token := ""
	if auth, ok := md["authorization"]; ok {
		token = strings.TrimPrefix(auth[0], "Bearer ")
	}

	// Your JWT validation logic here
	// Validate the JWT token and check its claims

	// For illustration purposes, assuming the token is valid if it's not empty
	if token == "" {
		return status.Errorf(codes.Unauthenticated, "invalid JWT token")
	}

	return nil
}

// generateResponse generates a response based on the client message
func generateResponse(message string) string {
	// Your chatbot logic here
	// For illustration purposes, echoing the client message
	return fmt.Sprintf("You said: %s", message)
}

func main() {
	// Create a listener on TCP port 6969
	lis, err := net.Listen("tcp", ":6969")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Create a new gRPC server with TLS credentials
	creds, err := credentials.NewServerTLSFromFile("server.crt", "server.key")
	if err != nil {
		log.Fatalf("failed to load credentials: %v", err)
	}
	opts := []grpc.ServerOption{grpc.Creds(creds)}
	grpcServer := grpc.NewServer(opts...)

	// Register the chatbot service with the server
	RegisterChatbotServer(grpcServer, &ChatbotServer{})

	// Start the gRPC server
	log.Println("gRPC server listening on port 6969")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
