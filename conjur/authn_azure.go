package conjur

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const AZURE_IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"

type AzureIdentityTokenGetResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

func GetAzureAccessToken() (string, error) {
	tok, err := GetAzureIdentityToken()
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

func GetAzureIdentityToken() (AzureIdentityTokenGetResponse, error) {
	// Create HTTP request for a managed services for Azure resources token to access Azure Resource Manager
	var msi_endpoint *url.URL
	msi_endpoint, err := url.Parse(AZURE_IMDS_ENDPOINT)
	if err != nil {
		return AzureIdentityTokenGetResponse{}, fmt.Errorf("error creating URL: %s", err.Error())
	}
	msi_parameters := msi_endpoint.Query()
	msi_parameters.Add("resource", "https://management.azure.com/")
	msi_endpoint.RawQuery = msi_parameters.Encode()
	req, err := http.NewRequest("GET", msi_endpoint.String(), nil)
	if err != nil {
		return AzureIdentityTokenGetResponse{}, fmt.Errorf("error creating HTTP request: %s", err.Error())
	}
	req.Header.Add("Metadata", "true")

	// Call managed services for Azure resources token endpoint
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return AzureIdentityTokenGetResponse{}, fmt.Errorf("error calling token endpoint: %s", err.Error())
	}

	// Pull out response body
	responseBytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return AzureIdentityTokenGetResponse{}, fmt.Errorf("error reading response body: %s", err.Error())
	}

	// Unmarshall response body into struct
	var r AzureIdentityTokenGetResponse
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		return AzureIdentityTokenGetResponse{}, fmt.Errorf("error unmarshalling the response: %s", err.Error())
	}

	return r, nil
}
