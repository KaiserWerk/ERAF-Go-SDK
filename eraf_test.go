package era

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"reflect"
	"testing"
)

func TestContainer_New(t *testing.T) {
	var (
		data interface{} = New()
	)

	if _, ok := data.(*Container); !ok {
		t.Errorf("Expected new *Container from New()")
	}
}

func TestContainer_GetVersionMajor(t *testing.T) {
	var (
		c             = New()
		expected byte = 150
	)
	c.SetVersionMajor(expected)

	if c.GetVersionMajor() != expected {
		t.Errorf("Expected version major %d, got %d", expected, c.GetVersionMajor())
	}
}

func TestContainer_SetVersionMajor(t *testing.T) {
	var (
		c             = New()
		expected byte = 150
	)
	c.SetVersionMajor(expected)

	if c.GetVersionMajor() != expected {
		t.Errorf("Expected version major %d, got %d", expected, c.GetVersionMajor())
	}
}

func TestContainer_GetVersionMinor(t *testing.T) {
	var (
		c             = New()
		expected byte = 17
	)
	c.SetVersionMinor(expected)

	if c.GetVersionMinor() != expected {
		t.Errorf("Expected version minor %d, got %d", expected, c.GetVersionMinor())
	}
}

func TestContainer_SetVersionMinor(t *testing.T) {
	var (
		c             = New()
		expected byte = 17
	)
	c.SetVersionMinor(expected)

	if c.GetVersionMinor() != expected {
		t.Errorf("Expected version minor %d, got %d", expected, c.GetVersionMinor())
	}
}

func TestContainer_GetVersionPatch(t *testing.T) {
	var (
		c             = New()
		expected byte = 4
	)
	c.SetVersionPatch(expected)

	if c.GetVersionPatch() != expected {
		t.Errorf("Expected version patch %d, got %d", expected, c.GetVersionPatch())
	}
}

func TestContainer_SetVersionPatch(t *testing.T) {
	var (
		c             = New()
		expected byte = 4
	)
	c.SetVersionPatch(expected)

	if c.GetVersionPatch() != expected {
		t.Errorf("Expected version patch %d, got %d", expected, c.GetVersionPatch())
	}
}

func TestContainer_GetNonce(t *testing.T) {
	var (
		expected = []byte{1, 2, 3, 4, 5}
		c        = New().SetNonce(expected)
	)

	if !bytes.Equal(c.GetNonce(), expected) {
		t.Errorf("Expected nonce %#v, got %#v", expected, c.GetNonce())
	}
}

func TestContainer_SetNonce(t *testing.T) {
	var (
		expected = []byte{1, 2, 3, 4, 5}
		c        = New().SetNonce(expected)
	)

	if !bytes.Equal(c.GetNonce(), expected) {
		t.Errorf("Expected nonce %#v, got %#v", expected, c.GetNonce())
	}
}

func TestContainer_GetTag(t *testing.T) {
	var (
		expected = []byte{6, 7, 8, 9, 10}
		c        = New().SetTag(expected)
	)

	if !bytes.Equal(c.GetTag(), expected) {
		t.Errorf("Expected tag %#v, got %#v", expected, c.GetTag())
	}
}

func TestContainer_SetTag(t *testing.T) {
	var (
		expected = []byte{6, 7, 8, 9, 10}
		c        = New().SetTag(expected)
	)

	if !bytes.Equal(c.GetTag(), expected) {
		t.Errorf("Expected tag %#v, got %#v", expected, c.GetTag())
	}
}

func TestContainer_GetIdentifier(t *testing.T) {
	var (
		expected = []byte{75, 180, 50, 1}
		c        = New().SetIdentifier(expected)
	)

	if !bytes.Equal(c.GetIdentifier(), expected) {
		t.Errorf("Expected identifier %#v, got %#v", expected, c.GetIdentifier())
	}
}

func TestContainer_SetIdentifier(t *testing.T) {
	var (
		expected = []byte{75, 180, 50, 1}
		c        = New().SetIdentifier(expected)
	)

	if !bytes.Equal(c.GetIdentifier(), expected) {
		t.Errorf("Expected identifier %#v, got %#v", expected, c.GetIdentifier())
	}
}

func TestContainer_GetCertificate(t *testing.T) {
	var (
		expected = []byte(`-----BEGIN CERTIFICATE-----
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
		c        = New().SetCertificate(expected)
	)

	if !bytes.Equal(c.GetCertificate(), expected) {
		t.Errorf("Expected certificate %s, got %s", expected, c.GetCertificate())
	}
}

func TestContainer_SetCertificate(t *testing.T) {
	var (
		expected = []byte(`-----BEGIN CERTIFICATE-----
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
		c        = New().SetCertificate(expected)
	)

	if !bytes.Equal(c.GetCertificate(), expected) {
		t.Errorf("Expected certificate %s, got %s", expected, c.GetCertificate())
	}
}

func TestContainer_GetPrivateKey(t *testing.T) {
	var (
		expected = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
		c        = New().SetPrivateKey(expected)
	)

	if !bytes.Equal(c.GetPrivateKey(), expected) {
		t.Errorf("Expected private key %s, got %s", expected, c.GetPrivateKey())
	}
}

func TestContainer_SetPrivateKey(t *testing.T) {
	var (
		expected = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
		c        = New().SetPrivateKey(expected)
	)

	if !bytes.Equal(c.GetPrivateKey(), expected) {
		t.Errorf("Expected private key %s, got %s", expected, c.GetPrivateKey())
	}
}

func TestContainer_SetEmail(t *testing.T) {
	var (
		expected = []byte("myemail@cool-domain.com")
		c        = New().SetEmail(expected)
	)

	if !bytes.Equal(c.GetEmail(), expected) {
		t.Errorf("Expected email %s, got %s", expected, c.GetEmail())
	}
}

func TestContainer_GetEmail(t *testing.T) {
	var (
		expected = []byte("myemail@cool-domain.com")
		c        = New().SetEmail(expected)
	)

	if !bytes.Equal(c.GetEmail(), expected) {
		t.Errorf("Expected email %s, got %s", expected, c.GetEmail())
	}
}

func TestContainer_SetUsername(t *testing.T) {
	var (
		expected = []byte("My Super cool Username")
		c        = New().SetUsername(expected)
	)

	if !bytes.Equal(c.GetUsername(), expected) {
		t.Errorf("Expected email %s, got %s", expected, c.GetUsername())
	}
}

func TestContainer_GetUsername(t *testing.T) {
	var (
		expected = []byte("My Super cool Username")
		c        = New().SetUsername(expected)
	)

	if !bytes.Equal(c.GetUsername(), expected) {
		t.Errorf("Expected email %s, got %s", expected, c.GetUsername())
	}
}

func TestContainer_SetToken(t *testing.T) {
	var (
		expected = make([]byte, 15)
		c        = New()
	)

	_, err := rand.Read(expected)
	if err != nil {
		t.Errorf("generate token error: %s", err.Error())
	}
	c.SetToken(expected)

	if !bytes.Equal(c.GetToken(), expected) {
		t.Errorf("Expected token %#v, got %#v", expected, c.GetToken())
	}
}

func TestContainer_GetToken(t *testing.T) {
	var (
		expected = make([]byte, 15)
		c        = New()
	)

	_, err := rand.Read(expected)
	if err != nil {
		t.Errorf("generate token error: %s", err.Error())
	}
	c.SetToken(expected)

	if !bytes.Equal(c.GetToken(), expected) {
		t.Errorf("Expected token %#v, got %#v", expected, c.GetToken())
	}
}

func TestContainer_SetSignature(t *testing.T) {
	var (
		expected = make([]byte, 32)
		c        = New()
	)

	_, err := rand.Read(expected)
	if err != nil {
		t.Errorf("generate signature error: %s", err.Error())
	}
	c.SetSignature(expected)

	if !bytes.Equal(c.GetSignature(), expected) {
		t.Errorf("Expected signature %#v, got %#v", expected, c.GetSignature())
	}
}

func TestContainer_GetSignature(t *testing.T) {
	var (
		expected = make([]byte, 32)
		c        = New()
	)

	_, err := rand.Read(expected)
	if err != nil {
		t.Errorf("generate signature error: %s", err.Error())
	}
	c.SetSignature(expected)

	if !bytes.Equal(c.GetSignature(), expected) {
		t.Errorf("Expected signature %#v, got %#v", expected, c.GetSignature())
	}
}

func TestContainer_GetRootCertificate(t *testing.T) {
	var (
		expected = []byte(`-----BEGIN CERTIFICATE-----
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
		c        = New().SetRootCertificate(expected)
	)

	if !bytes.Equal(c.GetRootCertificate(), expected) {
		t.Errorf("Expected root certificate %s, got %s", expected, c.GetRootCertificate())
	}
}

func TestContainer_SetRootCertificate(t *testing.T) {
	var (
		expected = []byte(`-----BEGIN CERTIFICATE-----
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
		c        = New().SetRootCertificate(expected)
	)

	if !bytes.Equal(c.GetRootCertificate(), expected) {
		t.Errorf("Expected root certificate %s, got %s", expected, c.GetRootCertificate())
	}
}

func TestContainer_GetSemVer(t *testing.T) {
	var (
		expected = "2.15.7"
		c = New()
	)
	c.SetVersionMajor(2).
	  SetVersionMinor(15).
	  SetVersionPatch(7)

	if c.GetSemVer() != expected {
		t.Errorf("expected semver '%s', got '%s'", expected, c.GetSemVer())
	}
}

func TestContainer_GetX509Certificate(t *testing.T) {
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
		t.Errorf("expected certificate as x509.Certificate, got error '%s'", err.Error())
	}
}

func TestContainer_GetTlsCertificate(t *testing.T) {
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
		t.Errorf("expected tls.Certificate, got error '%s'", err.Error())
	}
}

func TestContainer_GetX509RootCertificate(t *testing.T) {
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
		t.Errorf("expected root certificate as x509.Certificate, got error '%s'", err.Error())
	}
}

func TestContainer_Payload(t *testing.T) {

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

func TestContainer_Headers(t *testing.T) {
	c := New()
	if len(c.Headers()) != int(headerSize) {
		t.Fatal("wrong header block size")
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
//		{name: "empty", container: New(), args: args{s: make([]byte, 0, 100)}, want: int(headerSize) + 3, wantErr: true}, // headerSize + version bytes
//		{name: "with email", container: func() *Container {
//			return New().SetEmail([]byte("my@cool-domain.com"))
//		}(), args: args{s: make([]byte, 0, 100)}, want: 67, wantErr: true},  // headerSize + version bytes + email
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//
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

func TestContainer_PayloadLen(t *testing.T) {
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

func TestContainer_HeaderLen(t *testing.T) {
	tests := []struct {
		name      string
		container *Container
		want      int
	}{
		{name: "normal", container: New(), want: int(headerSize)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.HeaderLen(); got != tt.want {
				t.Errorf("HeaderLen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkUnmarshalFromFile(b *testing.B) {
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

func BenchmarkUnmarshalBytes(b *testing.B) {
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

func BenchmarkMarshal(b *testing.B) {
	var (
		container = New()
		err       error
	)
	for i := 0; i < b.N; i++ {
		err = container.Marshal(io.Discard)
		if err != nil {
			b.Error(err.Error())
		}
	}
}

func BenchmarkMarshalToFile(b *testing.B) {
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
