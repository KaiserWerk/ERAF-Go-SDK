# ERAF Go SDK

[![Go Report Card](https://goreportcard.com/badge/github.com/KaiserWerk/ERAF-Go-SDK)](https://goreportcard.com/report/github.com/KaiserWerk/ERAF-Go-SDK)
[![GitHub issues](https://img.shields.io/github/issues/KaiserWerk/ERAF-Go-SDK)](https://github.com/KaiserWerk/ERAF-Go-SDK/issues)
[![GitHub license](https://img.shields.io/github/license/KaiserWerk/ERAF-Go-SDK)](https://github.com/KaiserWerk/ERAF-Go-SDK/blob/master/LICENSE.md)

This is an SDK to read, edit and create *Entity-related Authentication Format* files, *entity* meaning
a person, a device, an app, an endpoint or whatever it is you want to authenticate.

There is of course some slight overhead. The data fields, like ``Certificate`` or ``Nonce`` can all
be empty, but there is always space reserved for headers, even if no data has been set yet.
This overhead currently amounts to __46 bytes__, plus 3 bytes for the version. If this is acceptable
for your use case, please give it a try and send feedback if it works out for you.

This is **Work in Progress** which means the library is still changing but currently mostly stable
and version 1 will arrive soon.

## Due tests

### Tested successfully on

* windows/amd64
* linux/amd64
* darwin/amd64

### Not yet tested

* Tests on other OS/Arch combinations ([Issue #4](https://github.com/KaiserWerk/ERAF-Go-SDK/issues/4)) 
* Integration tests in example applications

## Purpose

There are a lot of different ways to authenticate an entity. Using username and password, a bearer
token or a certificate are just a few examples. This format is for bundling different 
authentication information into a single, portable file, easily transmittable over the line, e.g. 
via HTTP or email. You can for example use the ``Nonce`` and ``Tag`` fields to save meta data for AES
encryption of the data (e.g. the certificate) and decrypt the content at the recipient's device.
This is just one example of the many possible use cases.

## Installation

Once the first stable version is tagged, you can download it with
``go get -u github.com/KaiserWerk/ERAF-Go-SDK@v1.0.0`` and add the import line 
``eraf "github.com/KaiserWerk/ERAF-Go-SDK`` to your Go file(s).

If you want the bleeding edge version from the master branch, just drop the ``@version``.

## Usage

### Creating and Marshalling

First, create a new ``*eraf.Container`` and fill it with data. ``Set`` calls for setting fields
can be chained.

```golang
cert, _ := ioutil.ReadFile("localhost.cert")
key, _ := ioutil.ReadFile("localhost.key")
sig := sha256.Sum256(cert)

container := eraf.New()
container.
	SetCertificate(cert).
	SetPrivateKey(key).
	SetSignature(sig[:])
```

Available fields (that means data blocks) for you to use are as follows:

* ``VersionMajor`` 
* ``VersionMinor`` 
* ``VersionPatch``
* ``Nonce``
* ``Tag``
* ``SerialNumber``
* ``Identifier``
* ``Certificate``
* ``PrivateKey``
* ``Email``
* ``Username``
* ``Token``
* ``Signature``
* ``RootCertificate``

The fields are not exported, that means they cannot be accessed directly. Instead, there is a setter and
a getter for each field.

The maximum size (amount of bytes) you can put into any field is that of an unsigned 16 bit integer, that
means **65,535** bytes which is about 64 KiB. Byte slices too large will be truncated.

Now, you can either marshal (serialize) the created *ERAF* container into an ``io.Writer``, directly 
into a file or into a byte slice:

```golang
// into a buffer
var b bytes.Buffer
err := container.Marshal(&b) // as a reference

// or into an http.ResponseWriter
func handler(w http.ResponseWriter, r *http.Request) {
	// some code here
	err := container.Marshal(w)
}

// or into a file
err := container.MarshalToFile("somefile.eraf") // the file extension does not matter, actually


// or just get a []byte
var s []byte = container.MarshalBytes()
```

### Reading and Unmarshalling

You can either read an *ERAF* container from an ``io.Reader``, directly from a file or from a byte slice:

```golang
// from an io.Reader
resp, _ := http.Do(req)
defer resp.Body.Close()
container := &eraf.Container{}
err := eraf.Unmarshal(resp.Body, &container)

// or directly from a file
container := &eraf.Container{}
err := eraf.UnmarshalFromFile("somefile.eraf", &container) // again, the extension doesn't matter

// or from a []byte
container := &eraf.Container{}
err := eraf.UnmarshalBytes(somebytes, container)
```

The *ERAF* container implements the ``io.Reader`` interface, so you can supply it as the 
body parameter for HTTP requests which will read the whole container into the request body:

```golang
container := &eraf.Container{
	// ...
}
req, err := http.NewRequest(http.MethodPost, "https://some-url.com/", container)
```

### Obtaining Information

Get some byte amount information:

```golang
// Total length
totalLen := container.Len()

// header length (currently constant 42 bytes)
headerLen := container.HeaderLen()

// payload length
payloadLen := container.PayloadLen()
```

### Obtaining data

Get the version as a properly constructed Semantic Version string:

```golang
versionStr := container.GetSemVer() // e.g. 2.14.8
```

For every ``Set`` method there is an equal ``Get`` method you can use to read the field from
the container, e.g.

```golang
n := container.GetNonce()
// or
u := container.GetUsername()
// etc
// ...
```

You can get just the headers or just the payload for custom parsing as you need:

```golang
// Just the headers
headers := container.Headers()

// Just the payload
payload := container.Payload()
```

### Certificate convenience functions

A basic assumption is that all certificate and private key data set is PEM-encoded.
For easier certificate handling, there are a few convenience functions:

```golang
c := &eraf.Container{
	// some fields
}

// obtain the certificate bytes as *x509.Certificate
x509Cert, err := c.GetX509Certificate()

// or certificate and private key combined as *tls.Certificate
tlsCert, err := c.GetTlsCertificate()

// and the root certificate
rootCert, err := c.GetX509RootCertificate()
```

## Encryption & Decryption

### Encryption

For every field, there is a method to encrypt it, e.g. for field ``Email`` there is a method
``b, err := container.EncryptEmail(key)`` which returns the email encrypted with AES using 
the given key.
A nonce is required and must be set beforehand using the ``SetNonce(n)`` method, otherwise an 
error will be returned. The nonce can be reused for subsequent calls.
This method does **not** alter the container.

If you want to encrypt all fields, use ``err := container.EncryptEverything(key)``. This method
**does** alter the container. A new nonce will be generated and set automatically.
This method replaces all field values with their respective encrypted values.

### Decryption

The decryption processes are the exact inverse of the encryption processes. E.g. use
``email, err := container.DecryptEmail(key)`` to just decrypt the email.

Otherwise, use ``err := container.DecryptEverything(key)`` to simply decrypt every field in place.

## Examples

1. [Simple example with encryption](examples/simple-encryption/main.go)
1. [Extended example with encryption and (un)marshalling](examples/extended-encryption-and-marshalling/main.go)
1. [Sending an encrypted ERAF container via HTTP](examples/http-client/main.go) and
   [Receiving an ERAF container via HTTP and decrypt it](examples/http-server/main.go)

## Tests

### Unit tests

Use ``go test ./...`` to run all unit tests. Not everything is covered yet. 
But everything should pass. :)

### Benchmark Tests

Use ``go test -bench=.`` to run all benchmark tests. Not everything is covered yet.

```
goos: windows
goarch: amd64
pkg: github.com/KaiserWerk/ERAF-Go-SDK
cpu: AMD FX(tm)-8320 Eight-Core Processor
BenchmarkUnmarshalFromFile-8       15057             83189 ns/op
BenchmarkUnmarshalBytes-8       26284489                43.90 ns/op
BenchmarkMarshal-8               7802852               158.0 ns/op
BenchmarkMarshalToFile-8          139986              8587 ns/op
PASS
coverage: 78.1% of statements
```