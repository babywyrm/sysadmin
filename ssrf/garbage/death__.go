package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
)

// Starship represents a starship in the API
type Starship struct {
	Name        string `json:"name"`
	Affiliation string `json:"affiliation"`
	Speed       string `json:"speed"`
	Weapons     string `json:"weapons"`
}

// Predefined list of starships
var starships = []Starship{
	{"USS Enterprise", "Federation", "Warp 9.6", "Phasers, Photon Torpedoes"},
	{"Romulan Warbird", "Romulan", "Warp 9.0", "Disruptors, Cloaking Device"},
	{"USS Voyager", "Federation", "Warp 9.975", "Phasers, Quantum Torpedoes"},
	{"D'deridex-class Warbird", "Romulan", "Warp 9.6", "Plasma Torpedoes, Cloaking Device"},
}

// Main function to start the server
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/starships", starshipHandler).Methods("GET")
	r.HandleFunc("/hidden/ssrf", ssrfHandler).Methods("POST") // Hidden SSRF endpoint

	// Start the server
	port := "8080"
	fmt.Printf("Starting server on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// starshipHandler returns the list of starships
func starshipHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(starships)
}

// ssrfHandler handles SSRF requests
func ssrfHandler(w http.ResponseWriter, r *http.Request) {
	// Get the 'url' from the request body
	var requestBody struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	url := requestBody.URL
	if url == "" {
		http.Error(w, "Missing 'url' in request body", http.StatusBadRequest)
		return
	}

	// Basic validation to restrict certain URLs
	if !isValidURL(url) {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Make a request to the provided URL
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, "Failed to make request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the response body to the client
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// isValidURL checks if the provided URL is valid and allowed
func isValidURL(url string) bool {
	// Allow only HTTP and HTTPS protocols
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return false
	}

	// Regex to allow localhost and internal IPs
	re := regexp.MustCompile(`^https?://(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`)
	return re.MatchString(url)
}

//
//

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
)

// Starship represents a starship in the API
type Starship struct {
	Name        string `json:"name"`
	Affiliation string `json:"affiliation"`
	Speed       string `json:"speed"`
	Weapons     string `json:"weapons"`
}

// Predefined list of starships
var starships = []Starship{
	{"USS Enterprise", "Federation", "Warp 9.6", "Phasers, Photon Torpedoes"},
	{"Romulan Warbird", "Romulan", "Warp 9.0", "Disruptors, Cloaking Device"},
	{"USS Voyager", "Federation", "Warp 9.975", "Phasers, Quantum Torpedoes"},
	{"D'deridex-class Warbird", "Romulan", "Warp 9.6", "Plasma Torpedoes, Cloaking Device"},
}

// Main function to start the server
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/starships", starshipHandler).Methods("GET")
	r.HandleFunc("/api/ssrf", ssrfHandler).Methods("POST") // SSRF endpoint

	// Start the server
	port := "8080"
	fmt.Printf("Starting server on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// starshipHandler returns the list of starships if accessed from the SSRF endpoint
func starshipHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the request is coming from the SSRF endpoint
	if r.Header.Get("X-From-SSRF") != "true" {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(starships)
}

// ssrfHandler handles SSRF requests
func ssrfHandler(w http.ResponseWriter, r *http.Request) {
	// Get the 'url' from the request body
	var requestBody struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	url := requestBody.URL
	if url == "" {
		http.Error(w, "Missing 'url' in request body", http.StatusBadRequest)
		return
	}

	// Basic validation to restrict certain URLs
	if !isValidURL(url) {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Make a request to the provided URL
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, "Failed to make request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return the response body to the client
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

// isValidURL checks if the provided URL is valid and allowed
func isValidURL(url string) bool {
	// Allow only HTTP and HTTPS protocols
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return false
	}

	// Regex to allow localhost and internal IPs
	re := regexp.MustCompile(`^https?://(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`)
	return re.MatchString(url)
}

//
//
