# ERAF Go SDK

This is an SDK to read, edit and create *Entity-related Authentication Format* files, *entity* meaning
a person, a device, an app, an endpoint or whatever it is you want to authenticate.

There is of course some slight overhead. The data fields, like ``Certificate`` or ``Nonce`` can all
be empty, but there is always space reserved for headers, even if no data has been set yet.
This overhead currently amounts to __42 bytes__, plus 3 bytes for the version. If this is acceptable
for your use case, please give it a try out and give feedback whether it works out for you.

## Due tests

This is a prototype implementation, using BigEndian, currently only tested on windows/amd64.

* Tests on other OS/Arch combinations
* Stress tests to check overall performance
* Integration tests

## Purpose

There are a lot of different ways to authenticate an entity. Using username and password, a bearer
token or a certificate are just a few examples. This format is for bundling different 
authentication information into a single, portable file, easily transmittable over the line, e.g. 
via HTTP or email. You can for example use the ``Nonce`` and ``Tag`` fields to save meta data for AES
encryption of the data (e.g. the certificate) and decrypt the content at the recipient's device.
This is just one example of the many possible use cases.

## Examples

### Creating and Marshalling

First, create a new ``*eraf.Container`` with the ``eraf.New()`` function (this is required so that 
headers are set up correctly) and fill it with data. ``Set`` calls can be chained.

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

Now, you can either marshal (serialize) the created *ERAF* container into an ``io.Writer`` 
or directly into a file:

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

You can either read an *ERAF* container from an ``io.Reader`` or directly from a file:

```golang
// from an io.Reader
resp, _ := http.Do(req)
defer resp.Body.Close()
var container eraf.Container
err := eraf.Unmarshal(resp.Body, &container)

// or directly from a file
var container eraf.Container
err := eraf.UnmarshalFromFile("somefile.eraf", &container) // Again, the extension doesn't matter

// or from a []byte
var container *eraf.Container
err := eraf.UnmarshalBytes(somebytes, container)
```

The *ERAF* container implements the ``io.Reader`` interface, so you can supply it as the 
body parameter for HTTP requests which will read the whole container into the request body:

```golang
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

Get the version as a proper Semantic Version string:

```golang
versionStr := container.Version() // e.g. 2.14.8, the build version is ignored
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

You can get just the headers and just the payload for custom parsing as you need:

```golang
// Just the headers
headers := container.Headers()

// Just the payload
payload := container.Payload()
```

## Encryption & Decryption

### Encryption

For every field, there is a method to encrypt it, e.g. for field ``email`` there is a method
``b, err := container.EncryptEmail(key)`` which returns the email encrypted with AES using 
the given key.
A nonce is required and must be set beforehand using the ``SetNonce(n)`` method, otherwise an 
error will be returned. This method does **not** alter the container.

If you want to encrypt all fields, use ``err := container.EncryptEverything(key)``. This method
**does** alter the container. A new nonce will be generated and set automatically.
This method replaces all field values with their respective encrypted values.

### Decryption

The decryption processes are the exact inverse of the encryption processes. E.g. use
``b, err := container.DecryptEmail(key)`` to just decrypt the email.

Otherwise, use ``err := container.DecryptEverything(key)`` to simply decrypt every field.

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