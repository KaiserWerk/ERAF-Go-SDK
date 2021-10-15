package main

import (
	"fmt"
	"io"
	"log"

	eraf "github.com/KaiserWerk/ERAF-Go-SDK"
)

func main() {
	c := eraf.New()

	// if you need to set one or a two fields, you can use the setter methods
	c.SetNonce([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})

	// if you want to set a lot of fields, set the fields directly and call c.CalculateHeader,
	// it is more performat
	c.Email = []byte("hallo@welt.com")
	c.Username = []byte("great and interesting username")
	c.Identifier = []byte{1, 55, 84, 254, 255, 14, 1, 2, 2, 0, 0, 1}
	c.CalculateHeaders()

	b := make([]byte, c.Len())
	n, err := c.Read(b)
	if err != nil && err != io.EOF {
		log.Fatalf("could not read into byte slice: %s\n", err.Error())
	}
	fmt.Printf("read %d bytes\n", n)

	fmt.Printf("len: %d\n", c.Len())
}
