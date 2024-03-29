package main

import (
	"fmt"
	"log"

	eraf "github.com/KaiserWerk/ERAF-Go-SDK"
)

var (
	aesKey = []byte("R081ctdcBJR3S32coUAIsVuLkjL9QyCD") // 32 bytes = AES-256

)

func main() {
	container := &eraf.Container{}
	container.SetUsername([]byte("my-cool-username"))

	fmt.Printf("username: %s\n", container.GetUsername())

	_ = container.SetRandomNonce()

	err := container.EncryptEverything(container.GetNonce(), aesKey)
	handleError(err)

	fmt.Printf("username (encrypted): %s\n", container.GetUsername())
	err = container.DecryptEverything(container.GetNonce(), aesKey)
	handleError(err)

	fmt.Printf("username: %s\n", container.GetUsername())
	fmt.Println("SUCCESS!")
}

func handleError(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}
