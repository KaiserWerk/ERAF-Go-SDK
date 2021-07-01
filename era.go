package era

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const headerSize uint8 = 27

// Container is the central struct to work with
type Container struct {
	headers            [headerSize]byte
	payload            []byte
	Nonce              []byte
	Tag                []byte
	SerialNumber       []byte
	PersonalIdentifier []byte
	Certificate        []byte
	PrivateKey         []byte
	Email              []byte
	Username           []byte
	Token              []byte
}

// Version returns the combination of all version elements as a semantic version string (without the build version)
func (c Container) Version() string {
	return fmt.Sprintf("%d.%d.%d", c.VersionMajor, c.VersionMinor, c.VersionPatch)
}

// Len return the total amount of bytes of the file
func (c Container) Len() int {
	return c.HeaderLen() + c.PayloadLen()
}

// HeaderLen returns the amount of bytes the header consists of
func (c Container) HeaderLen() int {
	return int(headerSize)
}

// PayloadLen returns the amount of bytes the payload takes up
// Returns -1 if the payload is not set
func (c Container) PayloadLen() int {
	return len(c.payload)
}

// Bytes returns the complete ERAF file as a []byte
func (c Container) Bytes() []byte {
	return append(c.headers[:], c.payload...)
}

func (c Container) Read(s []byte) (int64, error) {
	s = c.Bytes()
	return int64(c.Len()), nil
}

// Headers returns just the header array of the ERAF file
func (c Container) Headers() [headerSize]byte {
	return c.headers
}

// Payload returns just the payload part of the ERAF file
func (c Container) Payload() []byte {
	return c.payload
}

// MarshalToFile serializes the ERAF file into the given file
func (c Container) MarshalToFile(file string) error {
	fh, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0744)
	if err != nil {
		return err
	}
	defer fh.Close()

	return c.Marshal(fh)
}

// Marshal serializes the ERAF file into the given io.Writer
func (c Container) Marshal(w io.Writer) error {
	header := []byte{
		0, 4, // version
		4, 12, // nonce
		16, 16, // tag
		32, 0, 0, 0, 0, // certificate
		0, 0, 0, 0, 0, 0, 0, 0, // private key
		0, 0, 0, 0, 0, 0, 0, 0, // signature
	}

	certificateLength := uint32(len(c.Certificate))
	privKeyLength := uint32(len(c.PrivateKey))
	signatureLength := uint32(len(c.Signature))

	var offset uint32 = 32
	// certificate
	binary.BigEndian.PutUint32(header[7:11], certificateLength)
	offset += certificateLength
	// private key
	binary.BigEndian.PutUint32(header[11:15], offset)
	binary.BigEndian.PutUint32(header[15:19], privKeyLength)
	offset += privKeyLength
	// signature
	binary.BigEndian.PutUint32(header[19:23], offset)
	binary.BigEndian.PutUint32(header[23:], signatureLength)

	payload := append([]byte{c.VersionMajor, c.VersionMinor, c.VersionPatch, c.VersionBuild}, c.Nonce[:]...)
	payload = append(payload, c.Tag[:]...)
	payload = append(payload, c.Certificate...)
	payload = append(payload, c.PrivateKey...)
	payload = append(payload, c.Signature...)

	if len(c.payload) == 0 && len(payload) > 0 {
		c.payload = payload
	}

	total := append(header, payload...)

	_, err := w.Write(total)

	return err
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

// Unmarshal deserializes a ERAF file from the given io.Reader
func Unmarshal(r io.Reader, target *Container) error {
	allBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	if len(allBytes) == 0 {
		return fmt.Errorf("read 0 bytes")
	}

	headers := allBytes[:headerSize]
	copy(target.headers[:], headers)
	payload := allBytes[headerSize:]
	target.payload = payload

	/*** Version ***/
	versionPosition := headers[0]
	versionLength := headers[1]
	versionBytes := payload[versionPosition : versionPosition+versionLength]

	target.VersionMajor = versionBytes[0]
	target.VersionMinor = versionBytes[1]
	target.VersionPatch = versionBytes[2]
	target.VersionBuild = versionBytes[3]

	/*** Nonce ***/
	noncePosition := headers[2]
	nonceLength := headers[3]
	nonceBytes := payload[noncePosition : noncePosition+nonceLength]
	copy(target.Nonce[:], nonceBytes)

	/*** Tag ***/
	tagPosition := headers[4]
	tagLength := headers[5]
	tagBytes := payload[tagPosition : tagPosition+tagLength]
	copy(target.Tag[:], tagBytes)

	/*** Certificate ***/
	certPosition := headers[6]
	certLength := binary.BigEndian.Uint32(headers[7:11])
	certBytes := payload[certPosition : uint32(certPosition)+certLength]
	target.Certificate = certBytes

	privKeyPosition := binary.BigEndian.Uint32(headers[11:15])
	privKeyLength := binary.BigEndian.Uint32(headers[15:19])
	privKeyBytes := payload[privKeyPosition : privKeyPosition+privKeyLength]
	target.PrivateKey = privKeyBytes

	signaturePosition := binary.BigEndian.Uint32(headers[19:23])
	signatureLength := binary.BigEndian.Uint32(headers[23:])
	signatureBytes := payload[signaturePosition : signaturePosition+signatureLength]
	target.Signature = signatureBytes

	return nil
}
