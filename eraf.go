package eraf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const (
	headerSize   uint8 = 50
	blockMaxSize int   = 65535
)

var (
	headerBlock = [headerSize]byte{
		0, 3, // version (3 bytes)
		0, 0, 0, 0, // nonce
		0, 0, 0, 0, // tag
		0, 0, 0, 0, // serial number
		0, 0, 0, 0, // personal identifier
		0, 0, 0, 0, // certificate
		0, 0, 0, 0, // private key
		0, 0, 0, 0, // email
		0, 0, 0, 0, // username
		0, 0, 0, 0, // password
		0, 0, 0, 0, // token
		0, 0, 0, 0, // signature
		0, 0, 0, 0, // root certificate
	}
)

// Container is the central struct to work with
type Container struct {
	headers         [headerSize]byte
	versionMajor    byte
	versionMinor    byte
	versionPatch    byte
	nonce           []byte
	tag             []byte
	serialNumber    []byte
	identifier      []byte
	rootCertificate []byte
	certificate     []byte
	privateKey      []byte
	email           []byte
	username        []byte
	password        []byte
	token           []byte
	signature       []byte
}

// New creates a new *Container. Just convenience, not necessary.
func New() *Container {
	return &Container{
		headers: headerBlock,
	}
}

// GetVersionMajor returns the major version
func (c *Container) GetVersionMajor() byte {
	return c.versionMajor
}

// SetVersionMajor sets the major version
func (c *Container) SetVersionMajor(v byte) *Container {
	c.versionMajor = v
	return c
}

// GetVersionMinor returns the minor version
func (c *Container) GetVersionMinor() byte {
	return c.versionMinor
}

// SetVersionMinor sets the minor version
func (c *Container) SetVersionMinor(v byte) *Container {
	c.versionMinor = v
	return c
}

// GetVersionPatch returns the patch version
func (c *Container) GetVersionPatch() byte {
	return c.versionPatch
}

// SetVersionPatch sets the patch version
func (c *Container) SetVersionPatch(v byte) *Container {
	c.versionPatch = v
	return c
}

// GetNonce returns the nonce
func (c *Container) GetNonce() []byte {
	return c.nonce
}

// SetNonce sets a nonce
func (c *Container) SetNonce(n []byte) *Container {
	if len(n) <= blockMaxSize {
		c.nonce = n
	} else {
		c.nonce = n[:blockMaxSize]
	}
	return c
}

// GetTag returns the tag
func (c *Container) GetTag() []byte {
	return c.tag
}

// SetTag sets a tag
func (c *Container) SetTag(t []byte) *Container {
	if len(t) <= blockMaxSize {
		c.tag = t
	} else {
		c.tag = t[:blockMaxSize]
	}
	c.calculateHeaders()
	return c
}

// GetSerialNumber returns the serial number
func (c *Container) GetSerialNumber() []byte {
	return c.serialNumber
}

// SetSerialNumber sets a serial number
func (c *Container) SetSerialNumber(sn []byte) *Container {
	if len(sn) <= blockMaxSize {
		c.serialNumber = sn
	} else {
		c.serialNumber = sn[:blockMaxSize]
	}
	return c
}

// GetIdentifier returns the identifier
func (c *Container) GetIdentifier() []byte {
	return c.identifier
}

// SetIdentifier sets an identifier
func (c *Container) SetIdentifier(id []byte) *Container {
	if len(id) <= blockMaxSize {
		c.identifier = id
	} else {
		c.identifier = id[:blockMaxSize]
	}
	return c
}

// GetRootCertificate returns the root certificate
func (c *Container) GetRootCertificate() []byte {
	return c.rootCertificate
}

// SetRootCertificate sets a root certificate
func (c *Container) SetRootCertificate(rc []byte) *Container {
	if len(rc) <= blockMaxSize {
		c.rootCertificate = rc
	} else {
		c.rootCertificate = rc[:blockMaxSize]
	}
	return c
}

// GetCertificate returns the certificate
func (c *Container) GetCertificate() []byte {
	return c.certificate
}

// SetCertificate sets a certificate. For the convenience functions to work properly, the certificate expected to be in PEM format
func (c *Container) SetCertificate(cert []byte) *Container {
	if len(cert) <= blockMaxSize {
		c.certificate = cert
	} else {
		c.certificate = cert[:blockMaxSize]
	}
	return c
}

// GetPrivateKey returns the private key
func (c *Container) GetPrivateKey() []byte {
	return c.privateKey
}

// SetPrivateKey sets a private key. For the convenience functions to work properly, the key is expected to be in PEM format
func (c *Container) SetPrivateKey(pk []byte) *Container {
	if len(pk) <= blockMaxSize {
		c.privateKey = pk
	} else {
		c.privateKey = pk[:blockMaxSize]
	}
	return c
}

// GetEmail returns the email address
func (c *Container) GetEmail() []byte {
	return c.email
}

// SetEmail sets an email address
func (c *Container) SetEmail(e []byte) *Container {
	if len(e) <= blockMaxSize {
		c.email = e
	} else {
		c.email = e[:blockMaxSize]
	}
	return c
}

// GetUsername returns the username
func (c *Container) GetUsername() []byte {
	return c.username
}

// SetUsername sets a username
func (c *Container) SetUsername(u []byte) *Container {
	if len(u) <= blockMaxSize {
		c.username = u
	} else {
		c.username = u[:blockMaxSize]
	}
	return c
}

// GetPassword returns the password
func (c *Container) GetPassword() []byte {
	return c.password
}

// SetPassword sets a password
func (c *Container) SetPassword(p []byte) *Container {
	if len(p) <= blockMaxSize {
		c.password = p
	} else {
		c.password = p[:blockMaxSize]
	}
	return c
}

// GetToken returns the token
func (c *Container) GetToken() []byte {
	return c.token
}

// SetToken sets a token
func (c *Container) SetToken(t []byte) *Container {
	if len(t) <= blockMaxSize {
		c.token = t
	} else {
		c.token = t[:blockMaxSize]
	}
	return c
}

// GetSignature returns the signature
func (c *Container) GetSignature() []byte {
	return c.signature
}

// SetSignature sets a signature
func (c *Container) SetSignature(sig []byte) *Container {
	if len(sig) <= blockMaxSize {
		c.signature = sig
	} else {
		c.signature = sig[:blockMaxSize]
	}
	return c
}

// GetSemVer returns the combination of all version elements as a semantic version string
func (c *Container) GetSemVer() string {
	return fmt.Sprintf("%d.%d.%d", c.versionMajor, c.versionMinor, c.versionPatch)
}

// GetX509Certificate returns the certificate as *x509.Certificate
func (c *Container) GetX509Certificate() (*x509.Certificate, error) {
	if c.certificate == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	block, _ := pem.Decode(c.certificate)
	if block == nil {
		return nil, fmt.Errorf("PEM block is nil")
	}
	return x509.ParseCertificate(block.Bytes)
}

// GetTlsCertificate returns the certificate as *tls.Certificate
func (c *Container) GetTlsCertificate() (*tls.Certificate, error) {
	if c.certificate == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	if c.privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	cert, err := tls.X509KeyPair(c.certificate, c.privateKey)
	return &cert, err
}

// GetX509RootCertificate returns the root certificate as *x509.Certificate
func (c *Container) GetX509RootCertificate() (*x509.Certificate, error) {
	if c.rootCertificate == nil {
		return nil, fmt.Errorf("root certificate is nil")
	}
	block, _ := pem.Decode(c.rootCertificate)
	if block == nil {
		return nil, fmt.Errorf("PEM block is nil")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Len returns the total amount of bytes of the file
func (c *Container) Len() int {
	return c.HeaderLen() + c.PayloadLen()
}

// HeaderLen returns the amount of bytes the header consists of
func (c *Container) HeaderLen() int {
	return int(headerSize)
}

// PayloadLen returns the amount of bytes the payload takes up
func (c *Container) PayloadLen() int {
	return 3 + len(c.nonce) + len(c.tag) + len(c.serialNumber) + len(c.identifier) + len(c.certificate) +
		len(c.privateKey) + len(c.email) + len(c.username) + len(c.token) + len(c.signature)
}

// Read reads all bytes into s and returns the number of bytes read as well as an error
func (c *Container) Read(s []byte) (int, error) {
	n := copy(s, c.MarshalBytes())
	if n == 0 {
		return 0, nil
	}
	return n, io.EOF
}

// Headers returns just the header array of the ERAF file
func (c *Container) Headers() [headerSize]byte {
	return c.headers
}

// Payload returns just the payload part of the ERAF file
func (c *Container) Payload() []byte {
	b := append([]byte{c.versionMajor, c.versionMinor, c.versionPatch}, c.nonce...)
	b = append(b, c.tag...)
	b = append(b, c.serialNumber...)
	b = append(b, c.identifier...)
	b = append(b, c.certificate...)
	b = append(b, c.privateKey...)
	b = append(b, c.email...)
	b = append(b, c.username...)
	b = append(b, c.token...)
	return append(b, c.signature...)
}

// Marshal serializes the ERAF file into the given io.Writer
func (c *Container) Marshal(w io.Writer) error {
	total := c.MarshalBytes()
	_, err := w.Write(total)

	return err
}

// MarshalToFile serializes the ERAF file into the given file using the given file permissions
func (c *Container) MarshalToFile(file string, perms os.FileMode) error {
	c.calculateHeaders()
	fh, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perms)
	if err != nil {
		return err
	}
	defer func() {
		_ = fh.Close()
	}()

	return c.Marshal(fh)
}

// MarshalBytes serializes the container into a []byte
func (c *Container) MarshalBytes() []byte {
	c.calculateHeaders()

	payload := append([]byte{c.versionMajor, c.versionMinor, c.versionPatch}, c.nonce...)
	payload = append(payload, c.tag...)
	payload = append(payload, c.serialNumber...)
	payload = append(payload, c.identifier...)
	payload = append(payload, c.certificate...)
	payload = append(payload, c.privateKey...)
	payload = append(payload, c.email...)
	payload = append(payload, c.username...)
	payload = append(payload, c.token...)
	payload = append(payload, c.signature...)

	h := c.Headers()
	total := append(h[:], payload...)
	return total
}

// UnmarshalFromFile deserializes a ERAF from the given file
func UnmarshalFromFile(file string, target *Container) error {
	reader, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() {
		_ = reader.Close()
	}()

	return Unmarshal(reader, target)
}

// Unmarshal deserializes a ERAF file from the io.Reader into a *Container
func Unmarshal(r io.Reader, target *Container) error {
	allBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	if len(allBytes) == 0 {
		return fmt.Errorf("read 0 bytes")
	}

	return UnmarshalBytes(allBytes, target)
}

// UnmarshalBytes takes a []byte and a pointer to a target container and deserializes the []byte into the container,
// e.g.:
//
//  var b []byte // some data source
//  var c *eraf.Container = eraf.New()
//  err := eraf.Unmarshal(b, c)
func UnmarshalBytes(allBytes []byte, target *Container) error {
	if len(allBytes) < int(headerSize) {
		return fmt.Errorf("byte slice is not large enough")
	}
	headers := allBytes[:headerSize]
	copy(target.headers[:], headers)
	payload := allBytes[headerSize:]

	// Version
	versionPosition := headers[0]
	versionLength := headers[1]
	versionBytes := payload[versionPosition : versionPosition+versionLength]
	target.versionMajor = versionBytes[0]
	target.versionMinor = versionBytes[1]
	target.versionPatch = versionBytes[2]

	// nonce
	noncePosition := binary.BigEndian.Uint16(headers[2:4])
	nonceLength := binary.BigEndian.Uint16(headers[4:6])
	nonceBytes := payload[noncePosition : noncePosition+nonceLength]
	target.nonce = nonceBytes

	// tag
	tagPosition := binary.BigEndian.Uint16(headers[6:8])
	tagLength := binary.BigEndian.Uint16(headers[8:10])
	tagBytes := payload[tagPosition : tagPosition+tagLength]
	target.tag = tagBytes

	// serial number
	snPosition := binary.BigEndian.Uint16(headers[10:12])
	snLength := binary.BigEndian.Uint16(headers[12:14])
	snBytes := payload[snPosition : snPosition+snLength]
	target.serialNumber = snBytes

	// personal identifier
	piPosition := binary.BigEndian.Uint16(headers[14:16])
	piLength := binary.BigEndian.Uint16(headers[16:18])
	piBytes := payload[piPosition : piPosition+piLength]
	target.identifier = piBytes

	// certificate
	certPosition := binary.BigEndian.Uint16(headers[18:20])
	certLength := binary.BigEndian.Uint16(headers[20:22])
	certBytes := payload[certPosition : certPosition+certLength]
	target.certificate = certBytes

	// private key
	pkPosition := binary.BigEndian.Uint16(headers[22:24])
	pkLength := binary.BigEndian.Uint16(headers[24:26])
	pkBytes := payload[pkPosition : pkPosition+pkLength]
	target.privateKey = pkBytes

	// email
	emailPosition := binary.BigEndian.Uint16(headers[26:28])
	emailLength := binary.BigEndian.Uint16(headers[28:30])
	emailBytes := payload[emailPosition : emailPosition+emailLength]
	target.email = emailBytes

	// username
	usernamePosition := binary.BigEndian.Uint16(headers[30:32])
	usernameLength := binary.BigEndian.Uint16(headers[32:34])
	usernameBytes := payload[usernamePosition : usernamePosition+usernameLength]
	target.username = usernameBytes

	// token
	tokenPosition := binary.BigEndian.Uint16(headers[34:36])
	tokenLength := binary.BigEndian.Uint16(headers[36:38])
	tokenBytes := payload[tokenPosition : tokenPosition+tokenLength]
	target.token = tokenBytes

	// signature
	signaturePosition := binary.BigEndian.Uint16(headers[38:40])
	signatureLength := binary.BigEndian.Uint16(headers[40:42])
	signatureBytes := payload[signaturePosition : signaturePosition+signatureLength]
	target.signature = signatureBytes

	// root certificate
	rootCertPosition := binary.BigEndian.Uint16(headers[42:44])
	rootCertLength := binary.BigEndian.Uint16(headers[44:])
	rootCertBytes := payload[rootCertPosition : rootCertPosition+rootCertLength]
	target.rootCertificate = rootCertBytes

	target.calculateHeaders()

	return nil
}

// calculateHeaders sets the header bytes to correct values corresponding to field offsets and lengths. Will be
// called just before the *Container is marshalled.
func (c *Container) calculateHeaders() {
	header := headerBlock[:]

	var (
		versionLength     = uint16(3)
		nonceLength       = uint16(len(c.nonce))
		tagLength         = uint16(len(c.tag))
		snLength          = uint16(len(c.serialNumber))
		piLength          = uint16(len(c.identifier))
		certificateLength = uint16(len(c.certificate))
		privateKeyLength  = uint16(len(c.privateKey))
		emailLength       = uint16(len(c.email))
		usernameLength    = uint16(len(c.username))
		tokenLength       = uint16(len(c.token))
		signatureLength   = uint16(len(c.signature))
		rootCertLength    = uint16(len(c.rootCertificate))
	)

	var offset uint16 = 0

	// version
	// no need to set any values
	offset += versionLength

	// nonce
	binary.BigEndian.PutUint16(header[2:4], offset)
	binary.BigEndian.PutUint16(header[4:6], nonceLength)
	offset += nonceLength

	// tag
	binary.BigEndian.PutUint16(header[6:8], offset)
	binary.BigEndian.PutUint16(header[8:10], tagLength)
	offset += tagLength

	// serial number
	binary.BigEndian.PutUint16(header[10:12], offset)
	binary.BigEndian.PutUint16(header[12:14], snLength)
	offset += snLength

	// personal identifier
	binary.BigEndian.PutUint16(header[14:16], offset)
	binary.BigEndian.PutUint16(header[16:18], piLength)
	offset += piLength

	// certificate
	binary.BigEndian.PutUint16(header[18:20], offset)
	binary.BigEndian.PutUint16(header[20:22], certificateLength)
	offset += certificateLength

	// private key
	binary.BigEndian.PutUint16(header[22:24], offset)
	binary.BigEndian.PutUint16(header[24:26], privateKeyLength)
	offset += privateKeyLength

	// email
	binary.BigEndian.PutUint16(header[26:28], offset)
	binary.BigEndian.PutUint16(header[28:30], emailLength)
	offset += emailLength

	// username
	binary.BigEndian.PutUint16(header[30:32], offset)
	binary.BigEndian.PutUint16(header[32:34], usernameLength)
	offset += usernameLength

	// token
	binary.BigEndian.PutUint16(header[34:36], offset)
	binary.BigEndian.PutUint16(header[36:38], tokenLength)
	offset += tokenLength

	// signature
	binary.BigEndian.PutUint16(header[38:40], offset)
	binary.BigEndian.PutUint16(header[40:42], signatureLength)
	offset += signatureLength

	// root certificate
	binary.BigEndian.PutUint16(header[42:44], offset)
	binary.BigEndian.PutUint16(header[44:], rootCertLength) // leave upper bound open
	//offset += rootCertLength // no need to increase this further

	copy(c.headers[:], header)
}

// SetRandomNonce generates a 12-byte nonce (mainly for use with AES) and stores it
// into the nonce field
func (c *Container) SetRandomNonce() error {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	c.SetNonce(nonce)
	return nil
}

// EncryptEverything take a nonce and a key to encrypt every data block using AES in place.
// All blocks will be encrypted and written back, no data is returned. Requires a key with a length of
// 16 bytes (AES-128), 24 bytes (AES-192) or 32 bytes (AES-256).
// The nonce requires a length of 12 bytes. You can use SetRandomNonce() to generate a cryptographically secure nonce.
func (c *Container) EncryptEverything(nonce []byte, key []byte) error {
	sn, err := c.EncryptSerialNumber(nonce, key)
	if err != nil {
		return err
	}

	id, err := c.EncryptIdentifier(nonce, key)
	if err != nil {
		return err
	}

	cert, err := c.EncryptCertificate(nonce, key)
	if err != nil {
		return err
	}

	pk, err := c.EncryptPrivateKey(nonce, key)
	if err != nil {
		return err
	}

	email, err := c.EncryptEmail(nonce, key)
	if err != nil {
		return err
	}

	username, err := c.EncryptUsername(nonce, key)
	if err != nil {
		return err
	}

	token, err := c.EncryptToken(nonce, key)
	if err != nil {
		return err
	}

	sig, err := c.EncryptSignature(nonce, key)
	if err != nil {
		return err
	}

	rootCert, err := c.EncryptRootCertificate(nonce, key)
	if err != nil {
		return err
	}

	// everything or nothing
	// set the values only if no error occurs
	c.serialNumber = sn
	c.identifier = id
	c.certificate = cert
	c.privateKey = pk
	c.email = email
	c.username = username
	c.token = token
	c.signature = sig
	c.rootCertificate = rootCert

	c.calculateHeaders()

	return nil
}

// EncryptSerialNumber encrypts and returns the serial number
func (c *Container) EncryptSerialNumber(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.serialNumber, nonce)
}

// EncryptIdentifier encrypts and returns the identifier
func (c *Container) EncryptIdentifier(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.identifier, nonce)
}

// EncryptCertificate encrypts and returns the certificate
func (c *Container) EncryptCertificate(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.certificate, nonce)
}

// EncryptPrivateKey encrypts and returns the private key
func (c *Container) EncryptPrivateKey(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.privateKey, nonce)
}

// EncryptEmail encrypts and returns the email address
func (c *Container) EncryptEmail(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.email, nonce)
}

// EncryptUsername encrypts and returns the username
func (c *Container) EncryptUsername(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.username, nonce)
}

// EncryptToken encrypts and returns the token
func (c *Container) EncryptToken(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.token, nonce)
}

// EncryptSignature encrypts and returns the signature
func (c *Container) EncryptSignature(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.signature, nonce)
}

// EncryptRootCertificate encrypts and returns the signature
func (c *Container) EncryptRootCertificate(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.rootCertificate, nonce)
}

// DecryptEverything is the obvious counterpart to EncryptEverything. It performs the decryption in place, using
// either AES-128, AES-192 or AES-256, depending on key length.
func (c *Container) DecryptEverything(nonce []byte, key []byte) error {
	sn, err := c.DecryptSerialNumber(nonce, key)
	if err != nil {
		return err
	}

	id, err := c.DecryptIdentifier(nonce, key)
	if err != nil {
		return err
	}

	cert, err := c.DecryptCertificate(nonce, key)
	if err != nil {
		return err
	}

	pk, err := c.DecryptPrivateKey(nonce, key)
	if err != nil {
		return err
	}

	email, err := c.DecryptEmail(nonce, key)
	if err != nil {
		return err
	}

	username, err := c.DecryptUsername(nonce, key)
	if err != nil {
		return err
	}

	token, err := c.DecryptToken(nonce, key)
	if err != nil {
		return err
	}

	sig, err := c.DecryptSignature(nonce, key)
	if err != nil {
		return err
	}

	rootCert, err := c.DecryptRootCertificate(nonce, key)
	if err != nil {
		return err
	}

	// everything or nothing
	// TODO: use setters
	c.serialNumber = sn
	c.identifier = id
	c.certificate = cert
	c.privateKey = pk
	c.email = email
	c.username = username
	c.token = token
	c.signature = sig
	c.rootCertificate = rootCert

	c.calculateHeaders()

	return nil
}

// DecryptSerialNumber decrypts and returns the serial number
func (c *Container) DecryptSerialNumber(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.serialNumber, nonce)
}

// DecryptIdentifier decrypts and returns the identifier
func (c *Container) DecryptIdentifier(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.identifier, nonce)
}

// DecryptCertificate decrypts and returns the certificate
func (c *Container) DecryptCertificate(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.certificate, nonce)
}

// DecryptPrivateKey decrypts and returns the private key
func (c *Container) DecryptPrivateKey(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.privateKey, nonce)
}

// DecryptEmail decrypts and returns the email address
func (c *Container) DecryptEmail(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.email, nonce)
}

// DecryptUsername decrypts and returns the username
func (c *Container) DecryptUsername(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.username, nonce)
}

// DecryptToken decrypts and returns the token
func (c *Container) DecryptToken(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.token, nonce)
}

// DecryptSignature decrypts and returns the signature
func (c *Container) DecryptSignature(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.signature, nonce)
}

// DecryptRootCertificate decrypts and returns the root certificate
func (c *Container) DecryptRootCertificate(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.rootCertificate, nonce)
}

// Dump just writes all field contents into an io.Writer
func (c *Container) Dump(w io.Writer) {
	if w == nil {
		return
	}

	_, _ = fmt.Fprintf(w, "Semantic Version: %s\n", c.GetSemVer())
	_, _ = fmt.Fprintf(w, "Serial number: %s\n", c.GetSerialNumber())
	_, _ = fmt.Fprintf(w, "identifier: %s\n", c.GetIdentifier())
	_, _ = fmt.Fprintf(w, "certificate: %s\n", c.GetCertificate())
	_, _ = fmt.Fprintf(w, "Private Key: %s\n", c.GetPrivateKey())
	_, _ = fmt.Fprintf(w, "email: %s\n", c.GetEmail())
	_, _ = fmt.Fprintf(w, "username: %s\n", c.GetUsername())
	_, _ = fmt.Fprintf(w, "token: %s\n", c.GetToken())
	_, _ = fmt.Fprintf(w, "signature: %s\n", c.GetSignature())
	_, _ = fmt.Fprintf(w, "Root certificate: %s\n", c.GetRootCertificate())
}

func encryptAes(key []byte, s []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 && len(key) != 24 && len(key) != 16 {
		return nil, fmt.Errorf("expected key length 32, 24 or 16, got %d", len(key))
	}

	// don't decrypt if source is empty
	if len(s) == 0 {
		return []byte{}, nil
	}

	if len(nonce) == 0 {
		return nil, fmt.Errorf("missing nonce")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	b := aesGcm.Seal(nil, nonce, s, nil)

	return b, nil
}

func decryptAes(key []byte, s []byte, nonce []byte) ([]byte, error) {
	if len(key) != 32 && len(key) != 24 && len(key) != 16 {
		return nil, fmt.Errorf("expected key length 32, 24 or 16 bytes, got %d", len(key))
	}

	// don't encrypt if source is empty
	if len(s) == 0 {
		return []byte{}, nil
	}

	if len(nonce) == 0 {
		return nil, fmt.Errorf("missing nonce")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	b, err := aesGcm.Open(nil, nonce, s, nil)
	if err != nil {
		return nil, err
	}

	return b, nil
}
