package conjur

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	AZURE_IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"
)

type AzureProvider struct {
	Client           *Client
	RefreshRequested bool
	ServiceID        string
	HostID           string
}

type AzureIdentityTokenGetResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    string `json:"expires_in"`
	ExpiresOn    string `json:"expires_on"`
	NotBefore    string `json:"not_before"`
	Resource     string `json:"resource"`
	TokenType    string `json:"token_type"`
}

func (azp *AzureProvider) RefreshToken() error {
	err := azp.RefreshConjurTokenWithAzureProvider()
	if err != nil {
		return fmt.Errorf("error refreshing conjur token with aws provider: %s", err.Error())
	}

	return nil
}
func WithAzureProvider(azp *AzureProvider) func(*Client) error {
	return func(c *Client) error {
		c.TokenProvider = azp
		azp.Client = c
		return nil
	}
}

func (azp *AzureProvider) RefreshConjurTokenWithAzureProvider() error {
	c := azp.Client
	req, err := azp.MakeAuthenticateRequest()
	if err != nil {
		return fmt.Errorf("error making az authenticate request: %s", err.Error())
	}

	resp, err := c.SendRequest(req)
	if err != nil {
		return fmt.Errorf("send az authenticate request failed: %s", err.Error())
	}
	respconjbody, berr := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if berr != nil {
		return fmt.Errorf("failed to decode conjur response body: %s", berr.Error())
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("conjur request returned non 2xx: (%d) %s", resp.StatusCode, string(respconjbody))
	}

	// At this point we should have a Conjur session token we can use to fetch the creds
	conjtoken, decerr := b64.StdEncoding.DecodeString(string(respconjbody))
	if decerr != nil {
		return fmt.Errorf("failed to decode conjur token: %s", decerr.Error())
	}
	tokexp := time.Now().Add(time.Minute * 8) // conjur session token duration is 8 minutes - REF: <https://docs.cyberark.com/conjur-open-source/Latest/en/Content/Developer/Conjur_Auth_REST_APIs.htm>
	stok := string(conjtoken)
	azp.Client.SessionToken = &stok
	azp.Client.SessionTokenExpiration = &tokexp
	return nil

}

func NewAzureProvider(options ...func(*AzureProvider) error) AzureProvider {
	p := AzureProvider{}
	for _, option := range options {
		option(&p)
	}
	return p
}
func WithServiceID(svcid string) func(*AzureProvider) error {
	return func(p *AzureProvider) error {
		p.ServiceID = svcid
		return nil
	}
}
func WithHostID(hostid string) func(*AzureProvider) error {
	return func(p *AzureProvider) error {
		p.HostID = hostid
		return nil
	}
}

func (azp *AzureProvider) MakeAuthenticateRequest() (*http.Request, error) {
	c := azp.Client
	conjidentity := url.QueryEscape(azp.HostID)

	// https://docs.cyberark.com/conjur-cloud/latest/en/Content/Developer/Conjur_API_Azure_Authenticator.htm
	// POST /api/authn-azure/{service-id}/conjur/{host-id}/authenticate
	conjauthurl := fmt.Sprintf("%s/authn-azure/%s/conjur/%s/authenticate",
		c.Config.ApiUrl,
		azp.ServiceID,
		conjidentity)

	tok, err := GetAzureAccessToken()
	if err != nil {
		return nil, err
	}
	body := []byte(fmt.Sprintf("jwt=%s", tok))

	// Conjur GO SDK does not support "authn-azure", yet, so, we make a direct REST call here
	reqconj, rcerr := http.NewRequest(http.MethodPost, conjauthurl, bytes.NewBuffer(body))
	if rcerr != nil {
		return nil, fmt.Errorf("failed to create new conjur request: %s", rcerr.Error())
	}

	reqconj.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	reqconj.Header.Add("Accept-Encoding", "base64")

	return reqconj, nil
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
