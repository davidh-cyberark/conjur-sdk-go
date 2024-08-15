package main

import (
	"fmt"
	"os"

	"github.com/davidh-cyberark/conjur-sdk-go/conjur"
)

func main() {
	tok, err := conjur.GetAzureAccessToken()
	if err != nil {
		fmt.Printf("error getting access token: %s", err.Error())
		os.Exit(1)
	}

	fmt.Printf("%s\n", tok)
}
