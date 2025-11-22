// Package main provides a secure and modern SSH client example with
// host key verification and structured error handling.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	// Allow runtime configuration.
	user := flag.String("user", os.Getenv("SSH_USER"), "SSH username")
	addr := flag.String("addr", os.Getenv("SSH_ADDR"), "SSH server address (host or IP)")
	port := flag.String("port", os.Getenv("SSH_PORT"), "SSH port (default 22)")
	keyPath := flag.String("key", filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"), "Private key path")
	knownHostsPath := flag.String("knownhosts", filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"), "Known hosts file")
	cmd := flag.String("cmd", "uptime", "Command to execute remotely")
	flag.Parse()

	if *user == "" || *addr == "" {
		log.Fatal("user and addr are required (set via flags or environment variables)")
	}

	client, err := newSSHClient(*user, *addr, *port, *keyPath, *knownHostsPath)
	if err != nil {
		log.Fatalf("failed to create SSH client: %v", err)
	}
	defer client.Close()

	output, err := runRemoteCommand(client, *cmd)
	if err != nil {
		log.Fatalf("command failed: %v", err)
	}

	fmt.Println(output)
}

func newSSHClient(user, host, port, keyPath, knownHostsPath string) (*ssh.Client, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("creating host key callback: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         5 * time.Second,
	}

	address := fmt.Sprintf("%s:%s", host, port)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("dialing SSH: %w", err)
	}

	return client, nil
}

func runRemoteCommand(client *ssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}
	defer session.Close()

	var stdout bytes.Buffer
	session.Stdout = &stdout

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-ctx.Done():
		return "", errors.New("command timed out")
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("running command: %w", err)
		}
	}

	return stdout.String(), nil
}

//
//
