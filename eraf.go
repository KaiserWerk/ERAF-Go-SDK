package era

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
	VersionMajor    byte
	VersionMinor    byte
	VersionPatch    byte
	Nonce           []byte
	Tag             []byte
	SerialNumber    []byte
	Identifier      []byte
	Certificate     []byte
	PrivateKey      []byte
	Email           []byte
	Username        []byte
	Password        []byte
	Token           []byte
	Signature       []byte
	RootCertificate []byte
}

// New creates a new *Container. Just convenience, not necessary.
func New() *Container {
	return &Container{
		headers: headerBlock,
	}
}

// GetVersionMajor returns the major version
func (c *Container) GetVersionMajor() byte {
	return c.VersionMajor
}

// SetVersionMajor sets the major version
func (c *Container) SetVersionMajor(v byte) *Container {
	c.VersionMajor = v
	return c
}

// GetVersionMinor returns the minor version
func (c *Container) GetVersionMinor() byte {
	return c.VersionMinor
}

// SetVersionMinor sets the minor version
func (c *Container) SetVersionMinor(v byte) *Container {
	c.VersionMinor = v
	return c
}

// GetVersionPatch returns the patch version
func (c *Container) GetVersionPatch() byte {
	return c.VersionPatch
}

// SetVersionPatch sets the patch version
func (c *Container) SetVersionPatch(v byte) *Container {
	c.VersionPatch = v
	return c
}

// GetNonce returns the nonce
func (c *Container) GetNonce() []byte {
	return c.Nonce
}

// SetNonce sets a nonce
func (c *Container) SetNonce(n []byte) *Container {
	if len(n) <= blockMaxSize {
		c.Nonce = n
	} else {
		c.Nonce = n[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetTag returns the tag
func (c *Container) GetTag() []byte {
	return c.Tag
}

// SetTag sets a tag
func (c *Container) SetTag(t []byte) *Container {
	if len(t) <= blockMaxSize {
		c.Tag = t
	} else {
		c.Tag = t[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetSerialNumber returns the serial number
func (c *Container) GetSerialNumber() []byte {
	return c.SerialNumber
}

// SetSerialNumber sets a serial number
func (c *Container) SetSerialNumber(sn []byte) *Container {
	if len(sn) <= blockMaxSize {
		c.SerialNumber = sn
	} else {
		c.SerialNumber = sn[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetIdentifier returns the identifier
func (c *Container) GetIdentifier() []byte {
	return c.Identifier
}

// SetIdentifier sets an identifier
func (c *Container) SetIdentifier(id []byte) *Container {
	if len(id) <= blockMaxSize {
		c.Identifier = id
	} else {
		c.Identifier = id[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetCertificate returns the certificate
func (c *Container) GetCertificate() []byte {
	return c.Certificate
}

// SetCertificate sets a certificate. For the convenience functions to work properly, it expected to be in PEM format
func (c *Container) SetCertificate(cert []byte) *Container {
	if len(cert) <= blockMaxSize {
		c.Certificate = cert
	} else {
		c.Certificate = cert[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetPrivateKey returns the private key
func (c *Container) GetPrivateKey() []byte {
	return c.PrivateKey
}

// SetPrivateKey sets a private key. For the convenience functions to work properly, it expected to be in PEM format
func (c *Container) SetPrivateKey(pk []byte) *Container {
	if len(pk) <= blockMaxSize {
		c.PrivateKey = pk
	} else {
		c.PrivateKey = pk[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetEmail returns the email address
func (c *Container) GetEmail() []byte {
	return c.Email
}

// SetEmail sets an email address
func (c *Container) SetEmail(e []byte) *Container {
	if len(e) <= blockMaxSize {
		c.Email = e
	} else {
		c.Email = e[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetUsername returns the username
func (c *Container) GetUsername() []byte {
	return c.Username
}

// SetUsername sets a username
func (c *Container) SetUsername(u []byte) *Container {
	if len(u) <= blockMaxSize {
		c.Username = u
	} else {
		c.Username = u[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetPassowrd returns the password
func (c *Container) GetPassowrd() []byte {
	return c.Password
}

// SetPassword sets a password
func (c *Container) SetPassword(p []byte) *Container {
	if len(p) <= blockMaxSize {
		c.Password = p
	} else {
		c.Password = p[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetToken returns the token
func (c *Container) GetToken() []byte {
	return c.Token
}

// SetToken sets a token
func (c *Container) SetToken(t []byte) *Container {
	if len(t) <= blockMaxSize {
		c.Token = t
	} else {
		c.Token = t[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetSignature returns the signature
func (c *Container) GetSignature() []byte {
	return c.Signature
}

// SetSignature sets a signature
func (c *Container) SetSignature(sig []byte) *Container {
	if len(sig) <= blockMaxSize {
		c.Signature = sig
	} else {
		c.Signature = sig[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetRootCertificate returns the root certificate
func (c *Container) GetRootCertificate() []byte {
	return c.RootCertificate
}

// SetRootCertificate sets a root certificate
func (c *Container) SetRootCertificate(rc []byte) *Container {
	if len(rc) <= blockMaxSize {
		c.RootCertificate = rc
	} else {
		c.RootCertificate = rc[:blockMaxSize]
	}
	c.CalculateHeaders()
	return c
}

// GetSemVer returns the combination of all version elements as a semantic version string
func (c *Container) GetSemVer() string {
	return fmt.Sprintf("%d.%d.%d", c.VersionMajor, c.VersionMinor, c.VersionPatch)
}

// GetX509Certificate returns the certificate as *x509.Certificate
func (c *Container) GetX509Certificate() (*x509.Certificate, error) {
	if c.Certificate == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	block, _ := pem.Decode(c.Certificate)
	if block == nil {
		return nil, fmt.Errorf("PEM block is nil")
	}
	return x509.ParseCertificate(block.Bytes)
}

// GetTlsCertificate returns the certificate as *tls.Certificate
func (c *Container) GetTlsCertificate() (*tls.Certificate, error) {
	if c.Certificate == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	if c.PrivateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	cert, err := tls.X509KeyPair(c.Certificate, c.PrivateKey)
	return &cert, err
}

// GetX509RootCertificate returns the root certificate as *x509.Certificate
func (c *Container) GetX509RootCertificate() (*x509.Certificate, error) {
	if c.RootCertificate == nil {
		return nil, fmt.Errorf("root certificate is nil")
	}
	block, _ := pem.Decode(c.RootCertificate)
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
	return 3 + len(c.Nonce) + len(c.Tag) + len(c.SerialNumber) + len(c.Identifier) + len(c.Certificate) +
		len(c.PrivateKey) + len(c.Email) + len(c.Username) + len(c.Token) + len(c.Signature)
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
	b := append([]byte{c.VersionMajor, c.VersionMinor, c.VersionPatch}, c.Nonce...)
	b = append(b, c.Tag...)
	b = append(b, c.SerialNumber...)
	b = append(b, c.Identifier...)
	b = append(b, c.Certificate...)
	b = append(b, c.PrivateKey...)
	b = append(b, c.Email...)
	b = append(b, c.Username...)
	b = append(b, c.Token...)
	return append(b, c.Signature...)
}

// MarshalToFile serializes the ERAF file into the given file using the given file permissions
func (c *Container) MarshalToFile(file string, perms os.FileMode) error {
	fh, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perms)
	if err != nil {
		return err
	}
	defer func() {
		_ = fh.Close()
	}()

	return c.Marshal(fh)
}

// Marshal serializes the ERAF file into the given io.Writer
func (c *Container) Marshal(w io.Writer) error {
	total := c.MarshalBytes()
	_, err := w.Write(total)

	return err
}

// MarshalBytes serializes the container into a []byte
func (c *Container) MarshalBytes() []byte {
	c.CalculateHeaders()

	payload := append([]byte{c.VersionMajor, c.VersionMinor, c.VersionPatch}, c.Nonce...)
	payload = append(payload, c.Tag...)
	payload = append(payload, c.SerialNumber...)
	payload = append(payload, c.Identifier...)
	payload = append(payload, c.Certificate...)
	payload = append(payload, c.PrivateKey...)
	payload = append(payload, c.Email...)
	payload = append(payload, c.Username...)
	payload = append(payload, c.Token...)
	payload = append(payload, c.Signature...)

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

// UnmarshalBytes takes a []byte and a pointer to a target container and deserializes the []byte into the container
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
	target.VersionMajor = versionBytes[0]
	target.VersionMinor = versionBytes[1]
	target.VersionPatch = versionBytes[2]

	// Nonce
	noncePosition := binary.BigEndian.Uint16(headers[2:4])
	nonceLength := binary.BigEndian.Uint16(headers[4:6])
	nonceBytes := payload[noncePosition : noncePosition+nonceLength]
	target.Nonce = nonceBytes

	// Tag
	tagPosition := binary.BigEndian.Uint16(headers[6:8])
	tagLength := binary.BigEndian.Uint16(headers[8:10])
	tagBytes := payload[tagPosition : tagPosition+tagLength]
	target.Tag = tagBytes

	// serial number
	snPosition := binary.BigEndian.Uint16(headers[10:12])
	snLength := binary.BigEndian.Uint16(headers[12:14])
	snBytes := payload[snPosition : snPosition+snLength]
	target.SerialNumber = snBytes

	// personal identifier
	piPosition := binary.BigEndian.Uint16(headers[14:16])
	piLength := binary.BigEndian.Uint16(headers[16:18])
	piBytes := payload[piPosition : piPosition+piLength]
	target.Identifier = piBytes

	// Certificate
	certPosition := binary.BigEndian.Uint16(headers[18:20])
	certLength := binary.BigEndian.Uint16(headers[20:22])
	certBytes := payload[certPosition : certPosition+certLength]
	target.Certificate = certBytes

	// private key
	pkPosition := binary.BigEndian.Uint16(headers[22:24])
	pkLength := binary.BigEndian.Uint16(headers[24:26])
	pkBytes := payload[pkPosition : pkPosition+pkLength]
	target.PrivateKey = pkBytes

	// email
	emailPosition := binary.BigEndian.Uint16(headers[26:28])
	emailLength := binary.BigEndian.Uint16(headers[28:30])
	emailBytes := payload[emailPosition : emailPosition+emailLength]
	target.Email = emailBytes

	// username
	usernamePosition := binary.BigEndian.Uint16(headers[30:32])
	usernameLength := binary.BigEndian.Uint16(headers[32:34])
	usernameBytes := payload[usernamePosition : usernamePosition+usernameLength]
	target.Username = usernameBytes

	// token
	tokenPosition := binary.BigEndian.Uint16(headers[34:36])
	tokenLength := binary.BigEndian.Uint16(headers[36:38])
	tokenBytes := payload[tokenPosition : tokenPosition+tokenLength]
	target.Token = tokenBytes

	// signature
	signaturePosition := binary.BigEndian.Uint16(headers[38:40])
	signatureLength := binary.BigEndian.Uint16(headers[40:42])
	signatureBytes := payload[signaturePosition : signaturePosition+signatureLength]
	target.Signature = signatureBytes

	// root certificate
	rootCertPosition := binary.BigEndian.Uint16(headers[42:44])
	rootCertLength := binary.BigEndian.Uint16(headers[44:])
	rootCertBytes := payload[rootCertPosition : rootCertPosition+rootCertLength]
	target.RootCertificate = rootCertBytes

	target.CalculateHeaders()

	return nil
}

// CalculateHeaders sets the header bytes to correct values corresponding to field offsets and lengths
func (c *Container) CalculateHeaders() {
	header := headerBlock[:]

	var (
		versionLength     = uint16(3)
		nonceLength       = uint16(len(c.Nonce))
		tagLength         = uint16(len(c.Tag))
		snLength          = uint16(len(c.SerialNumber))
		piLength          = uint16(len(c.Identifier))
		certificateLength = uint16(len(c.Certificate))
		privateKeyLength  = uint16(len(c.PrivateKey))
		emailLength       = uint16(len(c.Email))
		usernameLength    = uint16(len(c.Username))
		tokenLength       = uint16(len(c.Token))
		signatureLength   = uint16(len(c.Signature))
		rootCertLength    = uint16(len(c.RootCertificate))
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
// into the Nonce field
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
	c.SerialNumber = sn
	c.Identifier = id
	c.Certificate = cert
	c.PrivateKey = pk
	c.Email = email
	c.Username = username
	c.Token = token
	c.Signature = sig
	c.RootCertificate = rootCert

	c.CalculateHeaders()

	return nil
}

// EncryptSerialNumber encrypts and returns the serial number
func (c *Container) EncryptSerialNumber(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.SerialNumber, nonce)
}

// EncryptIdentifier encrypts and returns the identifier
func (c *Container) EncryptIdentifier(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.Identifier, nonce)
}

// EncryptCertificate encrypts and returns the certificate
func (c *Container) EncryptCertificate(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.Certificate, nonce)
}

// EncryptPrivateKey encrypts and returns the private key
func (c *Container) EncryptPrivateKey(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.PrivateKey, nonce)
}

// EncryptEmail encrypts and returns the email address
func (c *Container) EncryptEmail(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.Email, nonce)
}

// EncryptUsername encrypts and returns the username
func (c *Container) EncryptUsername(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.Username, nonce)
}

// EncryptToken encrypts and returns the token
func (c *Container) EncryptToken(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.Token, nonce)
}

// EncryptSignature encrypts and returns the signature
func (c *Container) EncryptSignature(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.Signature, nonce)
}

// EncryptRootCertificate encrypts and returns the signature
func (c *Container) EncryptRootCertificate(nonce []byte, key []byte) ([]byte, error) {
	return encryptAes(key, c.RootCertificate, nonce)
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
	c.SerialNumber = sn
	c.Identifier = id
	c.Certificate = cert
	c.PrivateKey = pk
	c.Email = email
	c.Username = username
	c.Token = token
	c.Signature = sig
	c.RootCertificate = rootCert

	c.CalculateHeaders()

	return nil
}

// DecryptSerialNumber decrypts and returns the serial number
func (c *Container) DecryptSerialNumber(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.SerialNumber, nonce)
}

// DecryptIdentifier decrypts and returns the identifier
func (c *Container) DecryptIdentifier(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.Identifier, nonce)
}

// DecryptCertificate decrypts and returns the certificate
func (c *Container) DecryptCertificate(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.Certificate, nonce)
}

// DecryptPrivateKey decrypts and returns the private key
func (c *Container) DecryptPrivateKey(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.PrivateKey, nonce)
}

// DecryptEmail decrypts and returns the email address
func (c *Container) DecryptEmail(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.Email, nonce)
}

// DecryptUsername decrypts and returns the username
func (c *Container) DecryptUsername(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.Username, nonce)
}

// DecryptToken decrypts and returns the token
func (c *Container) DecryptToken(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.Token, nonce)
}

// DecryptSignature decrypts and returns the signature
func (c *Container) DecryptSignature(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.Signature, nonce)
}

// DecryptRootCertificate decrypts and returns the root certificate
func (c *Container) DecryptRootCertificate(nonce []byte, key []byte) ([]byte, error) {
	return decryptAes(key, c.RootCertificate, nonce)
}

// Dump just writes all field contents into an io.Writer
func (c *Container) Dump(w io.Writer) {
	if w == nil {
		return
	}

	_, _ = fmt.Fprintf(w, "Semantic Version: %s\n", c.GetSemVer())
	_, _ = fmt.Fprintf(w, "Serial number: %s\n", c.GetSerialNumber())
	_, _ = fmt.Fprintf(w, "Identifier: %s\n", c.GetIdentifier())
	_, _ = fmt.Fprintf(w, "Certificate: %s\n", c.GetCertificate())
	_, _ = fmt.Fprintf(w, "Private Key: %s\n", c.GetPrivateKey())
	_, _ = fmt.Fprintf(w, "Email: %s\n", c.GetEmail())
	_, _ = fmt.Fprintf(w, "Username: %s\n", c.GetUsername())
	_, _ = fmt.Fprintf(w, "Token: %s\n", c.GetToken())
	_, _ = fmt.Fprintf(w, "Signature: %s\n", c.GetSignature())
	_, _ = fmt.Fprintf(w, "Root Certificate: %s\n", c.GetRootCertificate())
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
