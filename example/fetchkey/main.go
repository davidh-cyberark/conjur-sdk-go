package main

import (
	"log"

	"github.com/davidh-cyberark/conjur-sdk-go/v1/conjur"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

/*
Create a file, creds.toml with these parameters and fill in your values
# Conjur appliance url
APIURL = "https://YOUR-CONJUR-SUB-DOMAIN.secretsmgr.cyberark.cloud/api"

# Conjur account name
Account = "conjur"

# Conjur AWS region, usually us-east-1
AWSRegion = "us-east-1"

# Conjur ARN for role to assume
IAMRoleARN = "arn:aws:iam::0123456:role/myapplication_iam_role"

# Conjur identity configured for the role to authenticate against
Identity = "host/data/myapplication/0123456/myapplication_iam_role"

# Conjur authenticator id
Authenticator = "authn-iam/myapplication"

# For the `example/fetchkey`` code, add a key field
key = "data/vault/mysafe/my-long-identifier/address"
*/

func main() {
	k := koanf.New(".")
	err := k.Load(file.Provider("creds.toml"), toml.Parser())
	if err != nil {
		log.Fatalf("failed to load creds.toml: %s", err.Error())
	}

	key := k.String("key")
	if len(key) == 0 {
		log.Fatalf("failed to load `key` from creds.toml")
	}

	// These are the creds of the caller
	rolecreds := conjur.NewAWSProviderCredentials()

	// These are the creds that we want to call to Conjur with
	assumedrolecreds := conjur.NewAWSProviderCredentials(
		conjur.WithAWSProviderCredentialsArn(k.String("IAMRoleARN")))

	awsprovider := conjur.NewAWSProvider(
		conjur.WithRegion(k.String("AWSRegion")),
		conjur.WithAWSProviderRoleCredentials(rolecreds),
		conjur.WithAWSProviderAssumedRoleCredentials(assumedrolecreds))

	client := conjur.NewClient(k.String("APIURL"),
		conjur.WithAccount(k.String("Account")),
		conjur.WithIdentity(k.String("Identity")),
		conjur.WithAuthenticator(k.String("Authenticator")),
		conjur.WithAwsProvider(&awsprovider))

	val, err := client.FetchSecret(key)
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
	}

	log.Printf("Fetched Value: %s\n", string(val))
}
