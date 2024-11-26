package main

import (
	"log"

	"github.com/davidh-cyberark/conjur-sdk-go/conjur"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

func main() {
	k := koanf.New(".")
	err := k.Load(file.Provider("creds.toml"), toml.Parser())
	if err != nil {
		log.Fatalf("failed to load creds.toml: %s", err.Error())
	}

	key := k.String("pam.pcloudurlkey")
	if len(key) == 0 {
		log.Fatalf("failed to load `pam.pcloudurlkey` from creds.toml")
	}

	azureprovider := conjur.NewAzureProvider()
	client := conjur.NewClient(k.String("conjur.apiurl"),
		conjur.WithAccount(k.String("conjur.account")),
		conjur.WithAzureProvider(&azureprovider),
	)

	val, err := client.FetchSecret(key)
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
	}

	log.Printf("Fetched Value: %s\n", string(val))
}
