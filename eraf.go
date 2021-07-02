package era

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const (
	headerSize   uint8 = 42
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
		0, 0, 0, 0, // token
		0, 0, 0, 0, // signature
	}
)

// Container is the central struct to work with
type Container struct {
	headers            [headerSize]byte
	versionMajor       byte
	versionMinor       byte
	versionPatch       byte
	nonce              []byte
	tag                []byte
	serialNumber       []byte
	personalIdentifier []byte
	certificate        []byte
	privateKey         []byte
	email              []byte
	username           []byte
	token              []byte
	signature          []byte
}

func New() *Container {
	return &Container{
		headers: headerBlock,
	}
}

func (c *Container) GetVersionMajor() byte {
	return c.versionMajor
}

func (c *Container) SetVersionMajor(v byte) *Container {
	c.versionMajor = v
	return c
}

func (c *Container) GetVersionMinor() byte {
	return c.versionMinor
}

func (c *Container) SetVersionMinor(v byte) *Container {
	c.versionMinor = v
	return c
}

func (c *Container) GetVersionPatch() byte {
	return c.versionPatch
}

func (c *Container) SetVersionPatch(v byte) *Container {
	c.versionPatch = v
	return c
}

func (c *Container) GetNonce() []byte {
	return c.nonce
}

func (c *Container) SetNonce(n []byte) *Container {
	if len(n) <= blockMaxSize {
		c.nonce = n
	}
	return c
}

func (c *Container) GetTag() []byte {
	return c.tag
}

func (c *Container) SetTag(t []byte) *Container {
	if len(t) <= blockMaxSize {
		c.tag = t
	}
	return c
}

func (c *Container) GetSerialNumber() []byte {
	return c.serialNumber
}

func (c *Container) SetSerialNumber(sn []byte) *Container {
	if len(sn) <= blockMaxSize {
		c.serialNumber = sn
	}
	return c
}

func (c *Container) GetPersonalIdentifier() []byte {
	return c.personalIdentifier
}

func (c *Container) SetPersonalIdentifier(pi []byte) *Container {
	if len(pi) <= blockMaxSize {
		c.personalIdentifier = pi
	}
	return c
}

func (c *Container) GetCertificate() []byte {
	return c.certificate
}

func (c *Container) SetCertificate(cert []byte) *Container {
	if len(cert) <= blockMaxSize {
		c.certificate = cert
	}
	return c
}

func (c *Container) GetPrivateKey() []byte {
	return c.privateKey
}

func (c *Container) SetPrivateKey(pk []byte) *Container {
	if len(pk) <= blockMaxSize {
		c.privateKey = pk
	}
	return c
}

func (c *Container) GetEmail() []byte {
	return c.email
}

func (c *Container) SetEmail(e []byte) *Container {
	if len(e) <= blockMaxSize {
		c.email = e
	}
	return c
}

func (c *Container) GetUsername() []byte {
	return c.username
}

func (c *Container) SetUsername(u []byte) *Container {
	if len(u) <= blockMaxSize {
		c.username = u
	}
	return c
}

func (c *Container) GetToken() []byte {
	return c.token
}

func (c *Container) SetToken(t []byte) *Container {
	if len(t) <= blockMaxSize {
		c.token = t
	}
	return c
}

func (c *Container) GetSignature() []byte {
	return c.signature
}

func (c *Container) SetSignature(sig []byte) *Container {
	if len(sig) <= blockMaxSize {
		c.signature = sig
	}
	return c
}

// GetVersion returns the combination of all version elements as a semantic version string
func (c *Container) GetVersion() string {
	return fmt.Sprintf("%d.%d.%d", c.versionMajor, c.versionMinor, c.versionPatch)
}

// Len return the total amount of bytes of the file
func (c *Container) Len() int {
	return c.HeaderLen() + c.PayloadLen()
}

// HeaderLen returns the amount of bytes the header consists of
func (c *Container) HeaderLen() int {
	return int(headerSize)
}

// PayloadLen returns the amount of bytes the payload takes up
func (c *Container) PayloadLen() int {
	return 3 + len(c.nonce) + len(c.tag) + len(c.serialNumber) + len(c.personalIdentifier) + len(c.certificate) +
		len(c.privateKey) + len(c.email) + len(c.username) + len(c.token) + len(c.signature)
}

func (c *Container) Read(s []byte) (int, error) {
	s = c.MarshalBytes()
	return c.Len(), nil
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
	b = append(b, c.personalIdentifier...)
	b = append(b, c.certificate...)
	b = append(b, c.privateKey...)
	b = append(b, c.email...)
	b = append(b, c.username...)
	b = append(b, c.token...)
	return append(b, c.signature...)
}

// MarshalToFile serializes the ERAF file into the given file
func (c *Container) MarshalToFile(file string) error {
	fh, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0744)
	if err != nil {
		return err
	}
	defer fh.Close()

	return c.Marshal(fh)
}

// Marshal serializes the ERAF file into the given io.Writer
func (c *Container) Marshal(w io.Writer) error {

	total := c.MarshalBytes()

	_, err := w.Write(total)

	return err
}

func (c *Container) MarshalBytes() []byte {
	header := headerBlock[:]

	var (
		versionLength     = uint16(3)
		nonceLength       = uint16(len(c.nonce))
		tagLength         = uint16(len(c.tag))
		snLength          = uint16(len(c.serialNumber))
		piLength          = uint16(len(c.personalIdentifier))
		certificateLength = uint16(len(c.certificate))
		privKeyLength     = uint16(len(c.privateKey))
		emailLength       = uint16(len(c.email))
		usernameLength    = uint16(len(c.username))
		tokenLength       = uint16(len(c.token))
		signatureLength   = uint16(len(c.signature))
	)

	var offset uint16 = 0 //uint16(headerSize)

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
	binary.BigEndian.PutUint16(header[24:26], privKeyLength)
	offset += privKeyLength

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
	binary.BigEndian.PutUint16(header[40:], signatureLength) // leave upper bound open
	//offset += signatureLength // no need to increase this further

	payload := append([]byte{c.versionMajor, c.versionMinor, c.versionPatch}, c.nonce...)
	payload = append(payload, c.tag...)
	payload = append(payload, c.serialNumber...)
	payload = append(payload, c.personalIdentifier...)
	payload = append(payload, c.certificate...)
	payload = append(payload, c.privateKey...)
	payload = append(payload, c.email...)
	payload = append(payload, c.username...)
	payload = append(payload, c.token...)
	payload = append(payload, c.signature...)

	total := append(header, payload...)
	return total
}

// UnmarshalFromFile deserializes a ERAF from the given file
func UnmarshalFromFile(file string, target *Container) error {
	reader, err := os.Open(file)
	if err != nil {
		return err
	}
	defer reader.Close()

	return Unmarshal(reader, target)
}

// Unmarshal deserializes a ERAF file from the io.Reader into a *Container
func Unmarshal(r io.Reader, target *Container) error {
	allBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	if len(allBytes) == 0 {
		return fmt.Errorf("reader gave 0 bytes")
	}

	return UnmarshalBytes(allBytes, target)
}

func UnmarshalBytes(allBytes []byte, target *Container) error {
	if len(allBytes) < int(headerSize) {
		return fmt.Errorf("buffer is not large enough")
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

	// Nonce
	noncePosition := binary.BigEndian.Uint16(headers[2:4])
	nonceLength := binary.BigEndian.Uint16(headers[4:6])
	nonceBytes := payload[noncePosition : noncePosition+nonceLength]
	target.nonce = nonceBytes

	// Tag
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
	target.personalIdentifier = piBytes

	// Certificate
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
	signatureLength := binary.BigEndian.Uint16(headers[40:])
	signatureBytes := payload[signaturePosition : signaturePosition+signatureLength]
	target.signature = signatureBytes

	return nil
}

// EncryptEverything take a key to encrypt every data block using AES-256 in place. The nonce field is used to store
// meta data; if already set, it will be overwritten. All block will be encrypted and written back, no data is
// returned. Requires a key with a length of 16 bytes (AES-128), 24 bytes (AES-192) or 32 bytes (AES-256).
func (c *Container) EncryptEverything(key []byte) error {
	var (
		b []byte
		err error
	)

	// create and set nonce for further use
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	c.nonce = nonce

	if b, err = c.EncryptSerialNumber(key); err != nil {
		return err
	}
	c.serialNumber = b

	if b, err = c.EncryptPersonalIdentifier(key); err != nil {
		return err
	}
	c.personalIdentifier = b

	if b, err = c.EncryptCertificate(key); err != nil {
		return err
	}
	c.certificate = b

	if b, err = c.EncryptPrivateKey(key); err != nil {
		return err
	}
	c.privateKey = b

	if b, err = c.EncryptEmail(key); err != nil {
		return err
	}
	c.email = b

	if b, err = c.EncryptUsername(key); err != nil {
		return err
	}
	c.username = b

	if b, err = c.EncryptToken(key); err != nil {
		return err
	}
	c.token = b

	if b, err = c.EncryptSignature(key); err != nil {
		return err
	}
	c.signature = b

	return nil
}

func (c *Container) EncryptSerialNumber(key []byte) ([]byte, error) {
	return encryptAes(key, c.serialNumber, c.nonce)
}

func (c *Container) EncryptPersonalIdentifier(key []byte) ([]byte, error) {
	return encryptAes(key, c.personalIdentifier, c.nonce)
}

func (c *Container) EncryptCertificate(key []byte) ([]byte, error) {
	return encryptAes(key, c.certificate, c.nonce)
}

func (c *Container) EncryptPrivateKey(key []byte) ([]byte, error) {
	return encryptAes(key, c.privateKey, c.nonce)
}

func (c *Container) EncryptEmail(key []byte) ([]byte, error) {
	return encryptAes(key, c.email, c.nonce)
}

func (c *Container) EncryptUsername(key []byte) ([]byte, error) {
	return encryptAes(key, c.username, c.nonce)
}

func (c *Container) EncryptToken(key []byte) ([]byte, error) {
	return encryptAes(key, c.token, c.nonce)
}

func (c *Container) EncryptSignature(key []byte) ([]byte, error) {
	return encryptAes(key, c.signature, c.nonce)
}

// DecryptEverything is the obvious counterpart to EncryptEverything. It performs the decryption in place, using,
// depending on key length, either AES-128, AES-192 or AES-256.
func (c *Container) DecryptEverything(key []byte) error {
	var (
		b []byte
		err error
	)
	if b, err = c.DecryptSerialNumber(key); err != nil {
		return err
	}
	c.serialNumber = b

	if b, err = c.DecryptPersonalIdentifier(key); err != nil {
		return err
	}
	c.personalIdentifier = b

	if b, err = c.DecryptCertificate(key); err != nil {
		return err
	}
	c.certificate = b

	if b, err = c.DecryptPrivateKey(key); err != nil {
		return err
	}
	c.privateKey = b

	if b, err = c.DecryptEmail(key); err != nil {
		return err
	}
	c.email = b

	if b, err = c.DecryptUsername(key); err != nil {
		return err
	}
	c.username = b

	if b, err = c.DecryptToken(key); err != nil {
		return err
	}
	c.token = b

	if b, err = c.DecryptSignature(key); err != nil {
		return err
	}
	c.signature = b

	return nil
}

func (c *Container) DecryptSerialNumber(key []byte) ([]byte, error) {
	return decryptAes(key, c.serialNumber, c.nonce)
}

func (c *Container) DecryptPersonalIdentifier(key []byte) ([]byte, error) {
	return decryptAes(key, c.personalIdentifier, c.nonce)
}

func (c *Container) DecryptCertificate(key []byte) ([]byte, error) {
	return decryptAes(key, c.certificate, c.nonce)
}

func (c *Container) DecryptPrivateKey(key []byte) ([]byte, error) {
	return decryptAes(key, c.privateKey, c.nonce)
}

func (c *Container) DecryptEmail(key []byte) ([]byte, error) {
	return decryptAes(key, c.email, c.nonce)
}

func (c *Container) DecryptUsername(key []byte) ([]byte, error) {
	return decryptAes(key, c.username, c.nonce)
}

func (c *Container) DecryptToken(key []byte) ([]byte, error) {
	return decryptAes(key, c.token, c.nonce)
}

func (c *Container) DecryptSignature(key []byte) ([]byte, error) {
	return decryptAes(key, c.signature, c.nonce)
}

func encryptAes(key, s, nonce []byte) ([]byte, error) {
	if len(key) != 32 && len(key) != 24 && len(key) != 16 {
		return nil, fmt.Errorf("expected key length 32, 24 or 16, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	fmt.Println("unencrypted:", s)
	b := aesGcm.Seal(nil, nonce, s, nil)
	fmt.Println("encrypted:", b)

	return b, nil
}

func decryptAes(key, s, nonce []byte) ([]byte, error) {
	if len(key) != 32 && len(key) != 24 && len(key) != 16 {
		return nil, fmt.Errorf("expected key length 32, 24 or 16, got %d", len(key))
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