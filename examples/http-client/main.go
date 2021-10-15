package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	eraf "github.com/KaiserWerk/ERAF-Go-SDK"
)

var (
	aesKey = []byte("3d9p8MV0eFe2JeXe6YnD8RNjQ4GdbtNS")
)

func main() {
	container := eraf.New()
	err := container.SetRandomNonce()
	if err != nil {
		log.Fatal(err.Error())
	}

	container.SetEmail([]byte("my@cool-domain.com"))
	container.SetUsername([]byte("cool-user"))

	err = container.EncryptEverything(container.GetNonce(), aesKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	cl := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "http://localhost:9000/accept", container)
	if err != nil {
		log.Fatal(err.Error())
	}

	resp, err := cl.Do(req)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer resp.Body.Close()

	fmt.Println("Status:", resp.StatusCode)
}
