package main

import (
	"crypto/sha256"
	"fmt"
	"log"

	eraf "github.com/KaiserWerk/ERAF-Go-SDK"
)

var (
	aesKey = []byte("abc123def456ghi7") // 16 bytes = AES-128
)

func main() {

	createDummyEraf()

	container := &eraf.Container{}
	err := eraf.UnmarshalFromFile("good.eraf", container)
	if err != nil {
		log.Fatal("Error: " + err.Error())
	}

	fmt.Println("Version:", container.GetSemVer())
	fmt.Println("Header Length:", container.HeaderLen())
	fmt.Println("Payload Length:", container.PayloadLen())
	fmt.Println("Total Length:", container.Len())
	fmt.Println("Nonce:", container.GetNonce())
	fmt.Println("Tag:", container.GetTag())
	fmt.Println("SerialNumber:", container.GetSerialNumber())
	fmt.Println("Identifier:", container.GetIdentifier())
	fmt.Println("Email:", string(container.GetEmail()))
	email, err := container.DecryptEmail(container.GetNonce(), aesKey)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("Email:", string(email))

	fmt.Println("PI:", container.GetIdentifier())
	pi, err := container.DecryptIdentifier(container.GetNonce(), aesKey)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("PI:", pi)
	fmt.Println("Username:", string(container.GetUsername()))
	fmt.Println("Token:", string(container.GetToken()))
	fmt.Println("Signature:", container.GetSignature())

	fmt.Println("-------")
	err = container.DecryptEverything(container.GetNonce(), aesKey)
	if err != nil {
		log.Fatal("Error: " + err.Error())
	}

	fmt.Println("Version:", container.GetSemVer())
	fmt.Println("Header Length:", container.HeaderLen())
	fmt.Println("Payload Length:", container.PayloadLen())
	fmt.Println("Total Length:", container.Len())
	fmt.Println("Nonce:", container.GetNonce())
	fmt.Println("Tag:", container.GetTag())
	fmt.Println("SerialNumber:", container.GetSerialNumber())
	fmt.Println("Identifier:", container.GetIdentifier())
	fmt.Println("Email:", string(container.GetEmail()))

	err = container.MarshalToFile("test.eraf", 0700)
	if err != nil {
		fmt.Println("MarshalToFile error:", err.Error())
	}

}

func createDummyEraf() {
	var err error

	cert := []byte(`-----BEGIN CERTIFICATE-----
	MIICwzCCAaugAwIBAgIJAOUotzKKlJNFMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNV
	BAMTCWxvY2FsaG9zdDAeFw0yMTA2MDExOTU2MDRaFw0zMTA1MzAxOTU2MDRaMBQx
	EjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
	ggEBAMbzgJxe5wQpTJu3ph5ROgI4JLVHoU/GTZDQ4PxRUnKoG/S/5zuRLkS1v8BN
	wo5ETId6THaPpWxQsbU4XrynC7R6/pNVHHqoQl6tDr5Zzo9/fgAHerCYDwJ7wNsv
	rLTBc9ibjsZXVKdzr3UIAs6Y9maDEQDsFYiVvT4iBnw90p7zlSd+Y1KPBj/abwWV
	HK8tz1tkrsSVtAipkIE48H5xrWSn6zfEX959ibUb9MEG8kxoYCRtsUTrfe2HYCv/
	3WfyCOJ1FlWeW1Zs7D5hM1OUNMnTjrQq6CNsCVS/9KLUNAyhM8XVRv1eZe9RXDqW
	y0n0hYnB+5J/ijqMz3khvpbcknkCAwEAAaMYMBYwFAYDVR0RBA0wC4IJbG9jYWxo
	b3N0MA0GCSqGSIb3DQEBBQUAA4IBAQBagAOvZKRBj8T+4DX9NbzRNRjbXQg0taEg
	ybYKnbh6KOQd6hpk1oQ8nG1xj0qWJgCr48Qthg1mZyF4wroi0p3b/QBmZnqjweel
	Ykfb7Qzu6cI1qR5GPveYeIc9JXnNB8flw95+d4B5ozYzruwSglTBnPqo44Imhc5N
	NrahdQNtYIdQAinMb5SEvXrz1SsAqkHmWcIxHnKFiHkNJ6q/EjtVEwXI/AiFaygv
	k9ucwYmQXsw8KLVPtd8nFd7+rNl17RkoLRWyKlxPd2pDJPR/EjFVuE17YPcPfDNo
	UiBKSNCwyEQDUZxL1ifPJnAoOXyCl/gl/FzRzmtKPfP2qeRey9jU
	-----END CERTIFICATE-----
	`)
	key := []byte(`-----BEGIN RSA PRIVATE KEY-----
	MIIEpAIBAAKCAQEAxvOAnF7nBClMm7emHlE6AjgktUehT8ZNkNDg/FFScqgb9L/n
	O5EuRLW/wE3CjkRMh3pMdo+lbFCxtThevKcLtHr+k1UceqhCXq0OvlnOj39+AAd6
	sJgPAnvA2y+stMFz2JuOxldUp3OvdQgCzpj2ZoMRAOwViJW9PiIGfD3SnvOVJ35j
	Uo8GP9pvBZUcry3PW2SuxJW0CKmQgTjwfnGtZKfrN8Rf3n2JtRv0wQbyTGhgJG2x
	ROt97YdgK//dZ/II4nUWVZ5bVmzsPmEzU5Q0ydOOtCroI2wJVL/0otQ0DKEzxdVG
	/V5l71FcOpbLSfSFicH7kn+KOozPeSG+ltySeQIDAQABAoIBAQCw2rEPUEWoK1ZQ
	blabSLV6V5I6G6zID43QF/6IDXpvNgVz8kuJZittJOuJ9RXoBcrJ++uQ0WzJ9omi
	gLOmnBAJpfQ74ELqvjwRkWEz0P2QDlNhj0R/Swy8tmnf7mdmXzmt6cpngiZcnLfy
	Hubv5IXU5tnsqfESc5nAa9q8AvECHhBYhgXRgJK9gfqNReWZHWxTg2P2Df1hHd3m
	F1GTUmqvvzeuHdBRoTsaQpfClgw5bRgSOECR46kanXb1TXsnTYU2Ym9WNPL0hlQj
	2rKrukTVOdaBk6231kXNI4siS4DOwhfUXRGt8Yh4v3e4Hn6eZpqc7IcSH3gQ+QUa
	v18iE1uJAoGBAOz3SFib99hJHpvfFsBb6F4iQFSOLhQ5ZdX0ONj6Bw6HK/K2fwmI
	PFS8YYmaSif6o14r3wIz1tCLPdlkZ39wgrTv0ALpcoWjQTAQPdkupdcwAHNE3Q7g
	L16GoAtRKpiNj24mmItjvWy+J0fkDiqZGRrv9+whR9Tz7+3CcfskhyLTAoGBANbu
	hje/YJfY4oLw6r7Lv4sTKM063pr4maP7bCOZPsiVW4awKODR1OlyDf89s+AOQCU9
	/mrSzfOwz1VJzbYRVyPFDTrBy9d8e7La1krVNOHMssIF8mPS+0qMIn54HkCRyPKr
	ecTJ1k8W7BVXe18UsGIstdaIrjYYeizz8vX3He4DAoGARvWRw38JC8pxkQmP/ZBI
	GBA3pVpiMAo0FYqpj0fn3xDZNzgw+IDEWDeFGbiLJkemrieDA1zUoeRgY/3uBDqD
	2XzKlGSlt6D4f1UNwEB4xuSH7fycGb1GUg8MU/c9Qyt43OpP2cXHTo3uo1eGanko
	DGn5mssogHt/yHnmuebpVKMCgYAqzSdHVMIsmxFImCd3RWXokTEv5YhM/jLCeCAp
	2qupEC1A3jXVx5OJxZ/J84StmsjlYboXldFTtSMkzeS8XCmpQuWGjO9GA1Ey5eeE
	0X6NdNEoWDzT6kEGsG9yFgOYQi/tO36tVLBr4Zm0Ck7UOW+CrXqstV1UAn3aE96P
	Yt2/9wKBgQDThEU8kWONFLpQI/sZrlLDrt50ipWL3v/xeWuQlfQCI2Lr0u6PktxD
	NSxw6yRw/jRiXRlL8+2eYsSqREqNNbgYYngv2v+futqfIuPaqlNVonbR/JXFPFVo
	vWlq4ZcJ6P2cq+IOGifZd5mYTSjGey7T6WFapo7bl7mnuwoDP4S40A==
	-----END RSA PRIVATE KEY-----
	`)
	sig := sha256.Sum256(cert)
	token := []byte("86ws5f248a6w4342f5662w4a46264462f4w4e6")

	container := eraf.New()
	container.VersionMajor = 1
	container.VersionMinor = 11
	container.VersionPatch = 4
	container.Nonce = []byte{1, 5, 14, 78, 251, 147, 95, 45, 14, 10, 64, 52}
	container.Tag = []byte{95, 45, 14, 10, 64, 52, 1, 5, 14, 78, 251, 147, 163, 32, 57, 199}
	container.SerialNumber = []byte{1, 5, 199, 0, 45}
	container.Identifier = []byte{1, 2, 3, 1}
	container.Certificate = cert
	container.PrivateKey = key
	container.Email = []byte("email@address.com")
	container.Username = []byte("my-cool-username")
	container.Token = token
	container.Signature = sig[:]
	container.CalculateHeaders()

	err = container.EncryptEverything(container.GetNonce(), aesKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = container.MarshalToFile("good.eraf", 0700)
	if err != nil {
		log.Fatal(err.Error())
	}
}
