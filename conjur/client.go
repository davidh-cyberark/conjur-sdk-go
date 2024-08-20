package conjur

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/cyberark/conjur-api-go/conjurapi"
)

const (
	Version          = "v1.0.0"
	defaultUserAgent = "conjur-sdk-go-client" + "/" + Version
)

type TokenProvider interface {
	RefreshToken() error
}

type Config struct {
	ApiUrl   string // required, Ex "https://YOUR-CONJUR-CLOUD-SUBDOMAIN.secretsmgr.cyberark.cloud/api",
	Account  string // required, Ex "conjur"
	Identity string // required, Ex "host/data/myapplication/AWS-ACCT-NUM/AWS_IAM_ROLE",

	Authenticator string // required when using an authenticator, ex "authn-iam/myapplication"
}

type Client struct {
	Config                 Config
	TokenProvider          TokenProvider
	SessionToken           *string
	SessionTokenExpiration *time.Time
}

func NewClient(url string, options ...func(*Client) error) *Client {
	c := Client{
		Config: Config{
			ApiUrl: url,
		},
	}
	for _, option := range options {
		option(&c)
	}
	return &c
}
func WithAccount(a string) func(*Client) error {
	return func(c *Client) error {
		c.Config.Account = a
		return nil
	}
}
func WithIdentity(id string) func(*Client) error {
	return func(c *Client) error {
		c.Config.Identity = id
		return nil
	}
}
func WithAuthenticator(a string) func(*Client) error {
	return func(c *Client) error {
		c.Config.Authenticator = a
		return nil
	}
}

func (c *Client) SendRequest(req *http.Request) (*http.Response, error) {
	httpclient := GetDefaultHTTPClient()
	return httpclient.Do(req)
}

// GetDefaultHTTPClient create http client with 30s timeout and no skip verify
func GetDefaultHTTPClient() *http.Client {
	return GetHTTPClient(time.Second*30, false)
}

// GetHTTPClient create http client for HTTPS
func GetHTTPClient(timeout time.Duration, skipverify bool) *http.Client {
	client := &http.Client{
		Timeout: timeout, /*time.Second * 30 */
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipverify, /* TLS_SKIP_VERIFY */
			},
		},
	}
	return client
}

func (c *Client) FetchSecret(key string) ([]byte, error) {
	config := conjurapi.Config{
		ApplianceURL: c.Config.ApiUrl,  // required
		Account:      c.Config.Account, // required
	}

	if c.TokenProvider == nil {
		return nil, fmt.Errorf("error: no token provider defined")
	}
	err := c.TokenProvider.RefreshToken()
	if err != nil {
		return nil, err
	}

	conjur, err := conjurapi.NewClientFromToken(config, *c.SessionToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create conjur client from token: %s", err.Error())
	}

	// Retrieve a secret into []byte.
	return conjur.RetrieveSecret(key)
}
