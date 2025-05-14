package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func main() {

	url := "https://dev-dnjvy3144huvo7sq.us.auth0.com/oauth/token"

	payload := strings.NewReader("{\"client_id\":\"k0E1lIIEmoeAdPknZk7bWdhUZiQT02Xa\",\"client_secret\":\"rPBwQYtHCs4kxjT3kdfVA0rV9DOOc1ETd3muOYYQo8QRsNfzi3E1w70wynJJR1Vn\",\"audience\":\"http://localhost:3010\",\"grant_type\":\"client_credentials\"}")

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error making HTTP request:", err)
		return
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	defer res.Body.Close()

	// Define a struct to unmarshal the response body

	// Unmarshal the response body into the struct
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		fmt.Println("Error unmarshaling response body:", err)
		return
	}

	// Access the access_token
	fmt.Println("Access Token:", tokenResponse.AccessToken)

	// Use the access token to make a request to the API
	apiURL := "http://localhost:3010/api/private-scoped"
	req, err = http.NewRequest("GET", apiURL, nil)
	if err != nil {
		fmt.Println("Error creating API request:", err)
		return
	}
	req.Header.Add("Authorization", "Bearer "+tokenResponse.AccessToken)

	// Debug output for request headers
	fmt.Println("Request Headers:")
	for key, values := range req.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", key, value)
		}
	}

	res, err = http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error making API request:", err)
		return
	}
	defer res.Body.Close()

	apiBody, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Println("Error reading API response body:", err)
		return
	}

	fmt.Println("API Response:", string(apiBody))
}
