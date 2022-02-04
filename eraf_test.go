package eraf

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func Test_Container_New(t *testing.T) {
	var (
		data interface{} = New()
	)

	c, ok := data.(*Container)
	if !ok {
		t.Fatalf("Expected new *Container from New()")
	}
	if c == nil {
		t.Fatalf("expected c to be not nil, but was nil")
	}
}

func Test_Container_VersionMajor(t *testing.T) {
	var (
		c             = New()
		expected byte = 150
	)
	c.SetVersionMajor(expected)

	if c.GetVersionMajor() != expected {
		t.Errorf("Expected version major %d, got %d", expected, c.GetVersionMajor())
	}
}

func Test_Container_VersionMinor(t *testing.T) {
	var (
		c             = New()
		expected byte = 17
	)
	c.SetVersionMinor(expected)

	if c.GetVersionMinor() != expected {
		t.Errorf("Expected version minor %d, got %d", expected, c.GetVersionMinor())
	}
}

func Test_Container_VersionPatch(t *testing.T) {
	var (
		c             = New()
		expected byte = 4
	)
	c.SetVersionPatch(expected)

	if c.GetVersionPatch() != expected {
		t.Errorf("Expected version patch %d, got %d", expected, c.GetVersionPatch())
	}
}

func Test_Container_Nonce(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"nonce length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"nonce too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetNonce(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetNonce()) {
				t.Errorf("Expected nonce len %d, got %d", len(tc.expectedOutput), len(tc.container.GetNonce()))
			}
		})
	}
}

func Test_Container_Tag(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"tag length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"tag too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetTag(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetTag()) {
				t.Errorf("Expected tag len %d, got %d", len(tc.expectedOutput), len(tc.container.GetTag()))
			}
		})
	}
}

func Test_Container_SerialNumber(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"serial number length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"serial number too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetSerialNumber(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetSerialNumber()) {
				t.Errorf("Expected serial number len %d, got %d", len(tc.expectedOutput), len(tc.container.GetSerialNumber()))
			}
		})
	}
}

func Test_Container_Identifier(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"identifier length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"identifier too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetIdentifier(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetIdentifier()) {
				t.Errorf("Expected identifier len %d, got %d", len(tc.expectedOutput), len(tc.container.GetIdentifier()))
			}
		})
	}
}

func Test_Container_RootCertificate(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"root certificate length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"root certificate too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetRootCertificate(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetRootCertificate()) {
				t.Errorf("Expected root certificate len %d, got %d", len(tc.expectedOutput), len(tc.container.GetRootCertificate()))
			}
		})
	}
}

func Test_Container_Certificate(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"certificate length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"certificate too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetCertificate(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetCertificate()) {
				t.Errorf("Expected certificate len %d, got %d", len(tc.expectedOutput), len(tc.container.GetCertificate()))
			}
		})
	}
}

func Test_Container_PrivateKey(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"private key length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"private key too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetPrivateKey(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetPrivateKey()) {
				t.Errorf("Expected private key len %d, got %d", len(tc.expectedOutput), len(tc.container.GetPrivateKey()))
			}
		})
	}
}

func Test_Container_Email(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"email length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"email too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetEmail(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetEmail()) {
				t.Errorf("Expected email len %d, got %d", len(tc.expectedOutput), len(tc.container.GetEmail()))
			}
		})
	}
}

func Test_Container_Username(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"username length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"username too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetUsername(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetUsername()) {
				t.Errorf("Expected username len %d, got %d", len(tc.expectedOutput), len(tc.container.GetUsername()))
			}
		})
	}
}

func Test_Container_Password(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"password length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"password too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetPassword(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetPassword()) {
				t.Errorf("Expected password len %d, got %d", len(tc.expectedOutput), len(tc.container.GetPassword()))
			}
		})
	}
}

func Test_Container_Token(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"token length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"token too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetToken(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetToken()) {
				t.Errorf("Expected token len %d, got %d", len(tc.expectedOutput), len(tc.container.GetToken()))
			}
		})
	}
}

func Test_Container_Signature(t *testing.T) {
	tests := []struct {
		name           string
		container      *Container
		input          []byte
		expectedOutput []byte
	}{
		{"signature length ok", New(), []byte{6, 7, 8, 9, 10}, []byte{6, 7, 8, 9, 10}},
		{"signature too long", New(), make([]byte, 65600), make([]byte, 65535)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.container.SetSignature(tc.input)
			if !bytes.Equal(tc.expectedOutput, tc.container.GetSignature()) {
				t.Errorf("Expected signature len %d, got %d", len(tc.expectedOutput), len(tc.container.GetSignature()))
			}
		})
	}
}

func Test_Container_GetSemVer(t *testing.T) {
	var (
		expected = "2.15.7"
		c        = New()
	)
	c.SetVersionMajor(2).
		SetVersionMinor(15).
		SetVersionPatch(7)

	if c.GetSemVer() != expected {
		t.Errorf("expected semver '%s', got '%s'", expected, c.GetSemVer())
	}
}

func Test_Container_GetX509Certificate(t *testing.T) {
	var (
		certBytes = []byte(`-----BEGIN CERTIFICATE-----
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
		c = New().SetCertificate(certBytes)
	)

	_, err := c.GetX509Certificate()
	if err != nil {
		t.Errorf("expected certificate as x509.certificate, got error '%s'", err.Error())
	}
}

func Test_Container_GetTlsCertificate(t *testing.T) {
	var (
		certBytes = []byte(`-----BEGIN CERTIFICATE-----
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
		pkBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
		c = New().SetCertificate(certBytes).SetPrivateKey(pkBytes)
	)

	_, err := c.GetTlsCertificate()
	if err != nil {
		t.Errorf("expected tls.certificate, got error '%s'", err.Error())
	}
}

func Test_Container_GetX509RootCertificate(t *testing.T) {
	var (
		certBytes = []byte(`-----BEGIN CERTIFICATE-----
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
		c = New().SetRootCertificate(certBytes)
	)

	_, err := c.GetX509RootCertificate()
	if err != nil {
		t.Errorf("expected root certificate as x509.certificate, got error '%s'", err.Error())
	}
}

func Test_Container_Len(t *testing.T) {
	tests := []struct {
		name      string
		container *Container
		want      int
	}{
		{name: "empty", container: New(), want: 53},
		{name: "with username", container: func() *Container {
			return New().SetUsername([]byte("mycoolusername"))
		}(), want: 67},
		{name: "with username and nonce", container: func() *Container {
			return New().SetUsername([]byte("mycoolusername")).SetNonce([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9})
		}(), want: 76},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.Len(); got != tt.want {
				t.Errorf("Len() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Container_HeaderLen(t *testing.T) {
	var (
		expected = int(headerSize)
		c        = New()
	)

	if c.HeaderLen() != expected {
		t.Errorf("expected header length %d, got %d", expected, c.HeaderLen())
	}
}

func Test_Container_PayloadLen(t *testing.T) {
	tests := []struct {
		name      string
		container *Container
		want      int
	}{
		{name: "empty", container: New(), want: 3},
		{name: "with personal identifier", container: func() *Container {
			return New().SetIdentifier([]byte{1, 3, 5, 7, 9})
		}(), want: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.PayloadLen(); got != tt.want {
				t.Errorf("PayloadLen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_Container_Headers(t *testing.T) {
	var (
		c       = New()
		headers = c.Headers()
	)

	if len(c.Headers()) != int(headerSize) {
		t.Fatal("wrong header block size")
	}

	if !bytes.Equal(headers[:], headerBlock[:]) {
		t.Errorf("expected default headers, got %#v instead", headers)
	}
}

func Test_Container_Payload(t *testing.T) {

	tests := []struct {
		name      string
		container *Container
		want      []byte
	}{
		{name: "empty", container: New(), want: []byte{0, 0, 0}},
		{name: "empty with version", container: func() *Container {
			return New().SetVersionMajor(14).
				SetVersionMinor(4).
				SetVersionPatch(144)
		}(), want: []byte{14, 4, 144}},
		{name: "with username", container: func() *Container {
			return New().SetUsername([]byte("my-cool-username"))
		}(), want: append([]byte{0, 0, 0}, []byte("my-cool-username")...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.Payload(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Payload() = %v, want %v", got, tt.want)
			}
		})
	}
}

//func TestContainer_Read(t *testing.T) {
//	type args struct {
//		s []byte
//	}
//	tests := []struct {
//		name      string
//		container *Container
//		args      args
//		want      int
//		wantErr   bool
//	}{
//		{name: "empty", container: New(), args: args{s: make([]byte, 0, 100)}, want: int(headerSize) + 3, wantErr: false}, // headerSize + version bytes
//		{name: "with email", container: func() *Container {
//			return New().SetEmail([]byte("my@cool-domain.com"))
//		}(), args: args{s: make([]byte, 0, 100)}, want: 67, wantErr: false}, // headerSize + version bytes + email
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got, err := tt.container.Read(tt.args.s)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if got != tt.want {
//				t.Errorf("Read() got = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}

func Test_Container_MarshalToFile(t *testing.T) {
	const (
		filenameEmpty                = "__empty.eraf"
		filenameEmptyFromConstructor = "__empty.eraf"
		filenameWithUsername         = "__empty_w_username.eraf"
	)
	type args struct {
		file  string
		perms os.FileMode
	}

	defer func() {
		_ = os.Remove(filenameEmpty)
		_ = os.Remove(filenameEmptyFromConstructor)
		_ = os.Remove(filenameWithUsername)
	}()

	tests := []struct {
		name      string
		container *Container
		args      args
		wantErr   bool
	}{
		{name: "empty", container: &Container{}, args: args{file: filenameEmpty, perms: 0700}, wantErr: false},
		{name: "empty from constructor", container: New(), args: args{file: filenameEmptyFromConstructor, perms: 0700}, wantErr: false},
		{name: "with username", container: New().SetUsername([]byte("my-cool-username")), args: args{file: filenameWithUsername, perms: 0700}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.container.MarshalToFile(tt.args.file, tt.args.perms); (err != nil) != tt.wantErr {
				t.Errorf("MarshalToFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Container_Marshal(t *testing.T) {
	type args struct {
		writer io.Writer
	}

	fh, err := ioutil.TempFile(os.TempDir(), "eraf-test-*")
	if err != nil {
		t.Fatalf("could not create temporary file")
	}
	defer func() {
		_ = fh.Close()
		_ = os.Remove(fh.Name())
	}()

	tests := []struct {
		name      string
		container *Container
		args      args
		wantErr   bool
	}{
		{name: "empty to buffer", container: &Container{}, args: args{writer: &bytes.Buffer{}}, wantErr: false},
		{name: "empty from constructor to discard", container: New(), args: args{writer: io.Discard}, wantErr: false},
		{name: "with username to file", container: New().SetUsername([]byte("my-cool-username")), args: args{writer: fh}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.container.Marshal(tt.args.writer); (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_Container_MarshalBytes(t *testing.T) {
	tests := []struct {
		name      string
		container *Container
		wantedLen int
	}{
		{name: "empty", container: &Container{}, wantedLen: 53},
		{name: "with email", container: (&Container{}).SetEmail([]byte("my-cool-email@abc.com")), wantedLen: 74},
		{name: "with tag", container: (&Container{}).SetTag([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}), wantedLen: 63},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.MarshalBytes(); len(got) != tt.wantedLen {
				t.Errorf("MarshalBytes() = %d, want %d", len(got), tt.wantedLen)
			}
		})
	}
}

/**
Benchmark tests
*/

func Benchmark_UnmarshalFromFile(b *testing.B) {
	const filename = "__bench_unmarshal_from_file.eraf"
	var (
		start     = New()
		err       error
		container = New()
	)

	err = start.MarshalToFile(filename, 0744)
	if err != nil {
		b.Fatal("could not marshal", err.Error())
	}
	defer func() {
		_ = os.Remove(filename)
	}()

	for i := 0; i < b.N; i++ {
		err = UnmarshalFromFile(filename, container)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}

func Benchmark_UnmarshalBytes(b *testing.B) {
	var (
		container = New()
		s         = New().MarshalBytes()
		err       error
	)

	for i := 0; i < b.N; i++ {
		err = UnmarshalBytes(s, container)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}

func Benchmark_Unmarshal(b *testing.B) {
	var (
		err error
		c   = New().SetEmail([]byte("some@email.com")).SetUsername([]byte("my cool username"))
		c2  = New()
	)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err = Unmarshal(c, c2); err != nil {
			b.Fatalf("could not Unmarshal from buffer: %s", err.Error())
		}
	}

}

func Benchmark_MarshalToFile(b *testing.B) {
	const filename = "__bench_marshal_to_file.eraf"
	var (
		container = New()
		err       error
	)
	fh, err := os.Create(filename)
	if err != nil {
		b.Fatal(err.Error())
	}

	defer func() {
		_ = os.Remove(filename)
	}()
	defer func() {
		_ = fh.Close()
	}()

	for i := 0; i < b.N; i++ {
		err = container.Marshal(fh)
		if err != nil {
			b.Errorf(err.Error())
		}
	}
}

func Benchmark_MarshalBytes(b *testing.B) {
	c := New().SetEmail([]byte("my@nice-domain.local")).SetIdentifier([]byte{1, 2, 3, 4, 5, 6, 7, 78, 8, 9, 9})
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = c.MarshalBytes()
	}
}

func Benchmark_Marshal(b *testing.B) {
	var (
		container = New()
		err       error
	)
	for i := 0; i < b.N; i++ {
		err = container.Marshal(io.Discard)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}

func Benchmark_calculateHeaders(b *testing.B) {
	c := New().SetEmail([]byte("cool@mailer.org")).SetPassword([]byte{1, 2, 3, 4, 5, 6, 7, 91})
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.calculateHeaders()
	}
}
