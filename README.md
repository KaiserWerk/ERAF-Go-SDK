# ERAF Go SDK
__IMPORTANT NOTICE: This is work in progress and currently in a non-functioning state!__

This is an SDK to read, edit and create *Entity-related Authentication Format* files, *entity* meaning
a person, a device, an app, an endpoint or whatever it is you want to authenticate.

This is a prototype implementation, using BigEndian, currently only tested on windows/amd64.
Tests on other OS/Arch combinations are due.

## Purpose

There are a lot of different ways to authenticate an entity. Using username and password, a bearer
token or a certificate are just a few examples. This format is for bundling different 
authentication information into a single, portable file, easily transmittable over the line, e.g. 
via HTTP. You can for example use the ``Nonce`` and ``Tag`` fields to save meta data for AES
encryption of data (e.g. the certificate) and decrypt the content at the recipients device.
This is just one example of the many possible use cases.

## Examples

### Creating and Marshalling

First, create a new ERAF ``container``  struct and fill it with data:

```golang
cert, _ := ioutil.ReadFile("localhost.cert")
key, _ := ioutil.ReadFile("localhost.key")
sig := sha256.Sum256(cert)

container := eraf.New()
```

Now, you can either marshal (serialize) the just created *ERAF* file into an ``io.Writer`` 
or directly into a file:

```golang
// to an io.Writer
var b bytes.Buffer
err := container.Marshal(&b) // as a reference

// or into a file
err := container.MarshalToFile("somefile.eraf") // the ending does not matter, actually
```

### Reading and Unmarshalling

You can either read a ``ERAF`` from an ``io.Reader`` or directly from a file:

```golang
// from an io.Reader
resp, _ := http.Do(req)
defer resp.Body.Close()
var container eraf.Container
err := eraf.Unmarshal(resp.Body, &container)

// or directly from a file
err := eraf.UnmarshalFromFile("somefile.eraf", &container) // Again, the ending doesn't matter
```

The *ERAF* Container implements the ``io.Reader`` interface, so you can easily supply it as a 
body parameter for HTTP requests:

```golang
req, _ := http.NewRequest(http.MethodPost, "https://some-url.com", container)
```

### Obtaining Information

Get some byte amount information:

```golang
// Total length
totalLen := container.Len()

// header length (currently constant 27 bytes)
headerLen := container.HeaderLen()

// payload length
payloadLen := container.PayloadLen()
```

### Obtaining data

Get the version as a proper Semantic Version string:

```golang
versionStr := container.Version() // e.g. 2.14.8, the build version is ignored
```

You can get just the headers and just the payload for custom parsing as you need:

```golang
// Just the headers
headers := container.Headers()

// Just the payload
payload := container.Payload()
```

Or, lastly, just get the complete ``ERAF`` as a byte slice:

```golang
allBytes := container.Bytes()
```

## Tests

### Unit tests

Use ``go test ./...`` to run all unit tests.

### Benchmark Tests

Use ``go test -bench=.`` to run all benchmark tests.

Here is a comparison for the ``Marshal()`` (to a byte buffer) and ``MarshalToFile()`` functions:

```
goos: windows
goarch: amd64
pkg: github.com/KaiserWerk/ERAFFile-Go-SDK
cpu: AMD FX(tm)-8320 Eight-Core Processor
BenchmarkERAFFile_Marshal-8                   178833              5904 ns/op
BenchmarkERAFFile_MarshalToFile-8               1910            605504 ns/op
PASS
```