package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"io"
	"encoding/gob"
	"encoding/base64"
	"regexp"
	"path/filepath"
)

// Hardcoded secret (Vulnerability: Hardcoded Secret)
const SECRET_KEY = "supersecretkey123"

// Exploit struct for deserialization vulnerability (Vulnerability: Deserialization)
type Exploit struct{}

// Remote code execution (RCE) vulnerability (Vulnerability: RCE)
func rceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		command := r.FormValue("command")
		// Vulnerable:  No input validation.
		cmd := exec.Command("/bin/sh", "-c", command) // Still vulnerable to command injection
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(w, "Error: %v\n", err)
		}
		fmt.Fprintf(w, "Output: %s\n", output)
	} else {
		// Serve a basic HTML form for the RCE endpoint.
		fmt.Fprint(w, `
			<form method="POST">
				<label for="command">Enter command:</label><br>
				<input type="text" id="command" name="command"><br>
				<input type="submit" value="Execute">
			</form>
		`)
	}
}

// Cross-site scripting (XSS) vulnerability (Vulnerability: XSS)
func xssHandler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	// Vulnerability: No output escaping.
	fmt.Fprintf(w, "Hello, %s", name)
}

// Directory traversal vulnerability (Vulnerability: Directory Traversal)
func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Please provide a filename.", http.StatusBadRequest)
		return
	}

	// Vulnerability: Missing proper path sanitization.
	// filepath := filepath.Join("uploads", filename) // Still vulnerable

	// More secure:
	baseDir := "uploads"
	filePath := filepath.Join(baseDir, filepath.Base(filename)) // Use filepath.Base
	
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found.", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Error opening file: %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set the Content-Type header.  Crucial for security!
	w.Header().Set("Content-Type", "application/octet-stream") //  Good default
	// Serve the file.
	_, err = io.Copy(w, file)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error serving file: %v", err), http.StatusInternalServerError)
		return
	}
}

// Deserialization vulnerability (Vulnerability: Deserialization)
func deserializeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		encodedData := r.FormValue("data")
		decodedData, err := base64.StdEncoding.DecodeString(encodedData)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error decoding base64: %v", err), http.StatusBadRequest)
			return
		}

		// Vulnerable: Deserialization of untrusted data.
		var obj interface{}
		decoder := gob.NewDecoder(strings.NewReader(string(decodedData))) // decodedData is a []byte, convert to string
		err = decoder.Decode(&obj)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error decoding gob: %v", err), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Deserialized: %v", obj) // Potential information leak
	} else {
		fmt.Fprint(w, "Send base64-encoded data to deserialize.")
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome to the Vulnerable Web App in Go!")
}

// Function with path manipulation vulnerability
func processData(userInput string) (string, error) {
	// Vulnerable:  No input validation
	// filePath := filepath.Join("/tmp/", userInput)
	// file, err := os.Create(filePath)
	// if err != nil {
	// 	return "", err
	// }
	// defer file.Close()
	// _, err = file.WriteString("Processed: " + userInput)
	// if err != nil{
	// 	return "", err
	// }
	// return fmt.Sprintf("Data processed and written to %s", filePath), nil

	// A slightly better approach:
	if !isValidInput(userInput) {
		return "", fmt.Errorf("invalid characters in input")
	}
	filePath := filepath.Join("/tmp/", userInput)
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	_, err = file.WriteString("Processed: " + userInput)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Data processed and written to %s", filePath), nil
}

func isValidInput(input string) bool {
	// Basic validation: Allow only alphanumeric characters, underscores, and hyphens.
	match, _ := regexp.MatchString("^[a-zA-Z0-9_-]+$", input)
	return match
}

func processHandler(w http.ResponseWriter, r *http.Request) {
	userData := r.FormValue("data")
	result, err := processData(userData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Fprint(w, result)
}

func main() {
	// Create the 'uploads' directory if it doesn't exist.
	if _, err := os.Stat("uploads"); os.IsNotExist(err) {
		os.Mkdir("uploads", 0755)
		// create a dummy file
		os.WriteFile("uploads/test.txt", []byte("This is a test file."), 0644)
	}

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/rce", rceHandler)
	http.HandleFunc("/xss", xssHandler)
	http.HandleFunc("/file", fileHandler)
	http.HandleFunc("/deserialize", deserializeHandler)
	http.HandleFunc("/process", processHandler)

	fmt.Println("Server listening on port 5001")
	http.ListenAndServe(":5001", nil)
}

// Simulate vulnerable xz-utils import.  Go doesn't have the xz-utils vulnerability,
// but this is included to demonstrate how a missing import might be flagged.
// func init() {
// 	decompressor, err := xz.NewReader(nil)  //  No equivalent in standard Go.
// 	if err != nil {
// 		fmt.Println("XZ init failed:", err)
// 	}
// 	fmt.Println(decompressor)
// }

//Simulate hallucinated import
// func someFunc() {
// 	nonExistentModule.SomeFunction()
// }

