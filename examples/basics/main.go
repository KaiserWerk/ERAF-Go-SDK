package main

import (
	"errors"
	"fmt"
	"io"
	"log"

	eraf "github.com/KaiserWerk/ERAF-Go-SDK"
)

func main() {
	c := eraf.New()

	c.SetNonce([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	c.SetEmail([]byte("hallo@welt.com"))
	c.SetUsername([]byte("great and interesting username"))
	c.SetIdentifier([]byte{1, 55, 84, 254, 255, 14, 1, 2, 2, 0, 0, 1})

	b := make([]byte, c.Len())
	n, err := c.Read(b)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Fatalf("could not read into byte slice: %s\n", err.Error())
	}
	fmt.Printf("read %d bytes\n", n)

	fmt.Printf("len: %d\n", c.Len())
}
