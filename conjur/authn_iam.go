package conjur

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	AWS_REGION_DEFAULT = "us-east-1"
)

// ConjurAWSIAMAuth struct used to serialize to JSON and post-body to Conjur API /authenticate
type AWSIAMAuth struct {
	Authorization string `json:"Authorization"`
	Date          string `json:"x-amz-date"`
	Token         string `json:"x-amz-security-token"`
	Host          string `json:"host"`
}

type AWSProvider struct {
	Region                        string
	RoleCredentials               AWSProviderCredentials // credentials for the current role
	AssumedRoleSessionCredentials AWSProviderCredentials // credentials obtained by assume role
	RefreshRequested              bool
	Client                        *Client
}

type AWSProviderCredentials struct {
	Arn             string
	Region          string // required
	AccessKey       string
	AccessSecret    string
	RoleSessionName string
	Expiration      time.Time
	SessionToken    string
}

func (ap *AWSProvider) RefreshToken() error {
	err := ap.RefreshConjurTokenWithAWSProvider()
	if err != nil {
		return fmt.Errorf("error refreshing conjur token with aws provider: %s", err.Error())
	}

	return nil
}

func WithAwsProvider(ap *AWSProvider) func(*Client) error {
	return func(c *Client) error {
		c.TokenProvider = ap
		ap.Client = c
		return nil
	}
}

func NewAWSProviderCredentials(options ...func(*AWSProviderCredentials) error) AWSProviderCredentials {
	p := AWSProviderCredentials{
		Arn:             "",
		AccessKey:       "",
		AccessSecret:    "",
		RoleSessionName: "",
	}
	for _, option := range options {
		option(&p)
	}
	if len(p.RoleSessionName) == 0 {
		r := RandSeq([]rune("abcdefghijklmnopqrstuvwxyz1234567890"), 5)
		p.RoleSessionName = fmt.Sprintf("conjurclient-%s-%s", Version, r)
	}
	return p
}
func WithAWSProviderCredentialsArn(arn string) func(*AWSProviderCredentials) error {
	return func(p *AWSProviderCredentials) error {
		p.Arn = arn
		return nil
	}
}
func WithAWSProviderCredentialsAccessKey(k string) func(*AWSProviderCredentials) error {
	return func(p *AWSProviderCredentials) error {
		p.AccessKey = k
		return nil
	}
}
func WithAWSProviderCredentialsAccessSecret(s string) func(*AWSProviderCredentials) error {
	return func(p *AWSProviderCredentials) error {
		p.AccessSecret = s
		return nil
	}
}
func WithAWSProviderCredentialsSessionToken(st string) func(*AWSProviderCredentials) error {
	return func(p *AWSProviderCredentials) error {
		p.SessionToken = st
		return nil
	}
}

func NewAWSProvider(options ...func(*AWSProvider) error) AWSProvider {
	p := AWSProvider{}
	for _, option := range options {
		option(&p)
	}
	if len(p.Region) == 0 {
		p.Region = AWS_REGION_DEFAULT
	}
	return p
}
func WithRegion(r string) func(*AWSProvider) error {
	return func(p *AWSProvider) error {
		p.Region = r
		return nil
	}
}
func WithAWSProviderRoleCredentials(c AWSProviderCredentials) func(*AWSProvider) error {
	return func(p *AWSProvider) error {
		p.RoleCredentials = c
		return nil
	}
}
func WithAWSProviderAssumedRoleCredentials(c AWSProviderCredentials) func(*AWSProvider) error {
	return func(p *AWSProvider) error {
		p.AssumedRoleSessionCredentials = c
		return nil
	}
}

func (ap *AWSProvider) MakeAuthenticateRequest() (*http.Request, error) {
	awsservice := "sts"
	awshost := fmt.Sprintf("%s.amazonaws.com", awsservice)
	awspath := "/"
	awsquery := "Action=GetCallerIdentity&Version=2011-06-15"

	awsurl := fmt.Sprintf("https://%s%s?%s", awshost, awspath, awsquery)

	awsregion := ap.Region
	awssigningtime := time.Now()

	req, reqerr := http.NewRequest(http.MethodGet, awsurl, nil)
	if reqerr != nil {
		return nil, fmt.Errorf("failed to create new conjur-aws-sts request: %s", reqerr.Error())
	}

	// sha256sum of empty string
	emptypayloadhashstring := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Conjur will use these creds to call IAM:GetCallerIdentity
	// Note: MUST use the access key/secret from the response and
	//       NOT the original access key/secret
	cnf := ap.AssumedRoleSessionCredentials
	awscreds := aws.Credentials{
		AccessKeyID:     cnf.AccessKey,
		SecretAccessKey: cnf.AccessSecret,
		SessionToken:    cnf.SessionToken,
	}

	mysigner := v4.NewSigner()
	sigerr := mysigner.SignHTTP(context.TODO(), awscreds, req, emptypayloadhashstring,
		awsservice, awsregion, awssigningtime)
	if sigerr != nil {
		return nil, fmt.Errorf("failed to sign request: %s", sigerr.Error())
	}

	reqstruct := &AWSIAMAuth{
		Authorization: req.Header.Get("Authorization"),
		Date:          req.Header.Get("X-Amz-Date"),
		Token:         req.Header.Get("X-Amz-Security-Token"),
		Host:          req.URL.Host,
	}
	reqheadersjson, rherr := json.Marshal(reqstruct)
	if rherr != nil {
		return nil, fmt.Errorf("failed to marshal header json: %s", rherr.Error())
	}

	c := ap.Client

	conjidentity := url.QueryEscape(c.Config.Identity)

	// https://docs.conjur.org/Latest/en/Content/Developer/Conjur_API_Authenticate.htm
	// POST /{authenticator}/{account}/{login}/authenticate
	conjauthurl := fmt.Sprintf("%s/%s/%s/%s/authenticate",
		c.Config.ApiUrl,
		c.Config.Authenticator,
		c.Config.Account,
		conjidentity)

	// Conjur GO SDK does not support "authn-iam", yet, so, we make a direct REST call here
	reqconj, rcerr := http.NewRequest(http.MethodPost, conjauthurl, bytes.NewBuffer(reqheadersjson))
	if rcerr != nil {
		return nil, fmt.Errorf("failed to create new conjur request: %s", rcerr.Error())
	}

	reqconj.Header.Add("Content-Type", "application/json")
	reqconj.Header.Add("Accept-Encoding", "base64")

	return reqconj, nil
}

func (ap *AWSProvider) RefreshConjurTokenWithAWSProvider() error {
	c := ap.Client

	// check if we have a valid token
	if c.SessionToken != nil && len(*c.SessionToken) != 0 && c.SessionTokenExpiration != nil && c.SessionTokenExpiration.Before(time.Now()) {
		return nil
	}

	// refresh AWS Role creds
	err := ap.RefreshAsumedRoleCredentials()
	if err != nil {
		return fmt.Errorf("error refreshing assumed role creds: %s", err.Error())
	}

	req, err := ap.MakeAuthenticateRequest()
	if err != nil {
		return fmt.Errorf("error making aws authenticate request: %s", err.Error())
	}

	resp, err := c.SendRequest(req)
	if err != nil {
		return fmt.Errorf("send aws authenticate request failed: %s", err.Error())
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
	ap.Client.SessionToken = &stok
	ap.Client.SessionTokenExpiration = &tokexp
	return nil
}

func (ap *AWSProvider) RefreshAsumedRoleCredentials() error {
	if len(ap.RoleCredentials.RoleSessionName) == 0 {
		return fmt.Errorf("error, no aws provider session name set")
	}
	var cfg aws.Config
	var err error
	if len(ap.RoleCredentials.AccessKey) != 0 && len(ap.RoleCredentials.AccessSecret) != 0 && len(ap.RoleCredentials.SessionToken) != 0 {
		cp := credentials.NewStaticCredentialsProvider(
			ap.RoleCredentials.AccessKey,
			ap.RoleCredentials.AccessSecret,
			ap.RoleCredentials.SessionToken)
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(cp))
	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO())
	}
	if err != nil {
		return fmt.Errorf("failed to load aws config: %s", err.Error())
	}
	stsclient := sts.NewFromConfig(cfg)

	// determine session role Arn from session creds
	id, err := stsclient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("error, GCI failed: %s", err.Error())
	}

	// If the role is same as the assumed role, then we use the creds from the role
	if ParamArnMatchesSessionArn(ap.AssumedRoleSessionCredentials.Arn, *id.Arn) {
		ap.AssumedRoleSessionCredentials = AWSProviderCredentials{
			Arn:          *id.Arn,
			AccessKey:    ap.RoleCredentials.AccessKey,
			AccessSecret: ap.RoleCredentials.AccessSecret,
			Expiration:   ap.RoleCredentials.Expiration,
			SessionToken: ap.RoleCredentials.SessionToken,
		}
		return nil
	}

	// different arn detected, so, we attempt to assume role
	assumeroleinput := &sts.AssumeRoleInput{
		RoleArn:         aws.String(ap.AssumedRoleSessionCredentials.Arn),
		RoleSessionName: aws.String(ap.AssumedRoleSessionCredentials.RoleSessionName),
	}
	assumeRoleResp, err := stsclient.AssumeRole(context.TODO(), assumeroleinput)
	if err != nil {
		return fmt.Errorf("failed to assume role: %s", err.Error())
	}
	if assumeRoleResp.AssumedRoleUser.Arn == nil {
		return fmt.Errorf("response did not contain AssumedRoleUser.Arn")
	}
	if assumeRoleResp.Credentials.AccessKeyId == nil {
		return fmt.Errorf("response did not contain Credentials.AccessKeyId")
	}
	if assumeRoleResp.Credentials.SecretAccessKey == nil {
		return fmt.Errorf("response did not contain Credentials.SecretAccessKey")
	}

	ap.AssumedRoleSessionCredentials = AWSProviderCredentials{
		Arn:          *assumeRoleResp.AssumedRoleUser.Arn,
		AccessKey:    *assumeRoleResp.Credentials.AccessKeyId,
		AccessSecret: *assumeRoleResp.Credentials.SecretAccessKey,
		Expiration:   *assumeRoleResp.Credentials.Expiration,
		SessionToken: *assumeRoleResp.Credentials.SessionToken,
	}

	return nil
}

func ParamArnMatchesSessionArn(paramarn string, callerarn string) bool {
	parn, perr := arn.Parse(paramarn)
	carn, cerr := arn.Parse(callerarn)
	if perr != nil || cerr != nil {
		return false
	}

	// check account and role name
	presparts := strings.Split(parn.Resource, "/")
	cresparts := strings.Split(carn.Resource, "/")
	return parn.AccountID == carn.AccountID && presparts[1] == cresparts[1]
}
