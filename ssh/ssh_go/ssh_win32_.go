package main

import (
	"fmt"
	"io"
	"log"
	"os/exec"

	"github.com/gliderlabs/ssh"
)

func main() {
	ssh.Handle(func(s ssh.Session) {
		_, _, isPty := s.Pty()
		if isPty {
			fmt.Println("PTY requested")

			cmd := exec.Command("powershell")
			stdin, err := cmd.StdinPipe()
			if err != nil {
				panic(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				panic(err)
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				panic(err)
			}

			go func() {
				io.Copy(stdin, s)
			}()
			go func() {
				io.Copy(s, stdout)
			}()
			go func() {
				io.Copy(s, stderr)
			}()

			err = cmd.Run()
			if err == nil {
				log.Println("session ended normally")
				s.Exit(0)
			} else {
				log.Printf("session ended with an error: %v\n", err)

				exitCode := 1
				if exitError, ok := err.(*exec.ExitError); ok {
					exitCode = exitError.ExitCode()
					log.Printf("exit code: %d\n", exitCode)
				}

				s.Exit(exitCode)
			}
		} else {
			io.WriteString(s, "No PTY requested.\n")
			s.Exit(1)
		}
	})

	log.Println("starting ssh server on port 2824...")
	log.Fatal(ssh.ListenAndServe(":2824", nil))
}
