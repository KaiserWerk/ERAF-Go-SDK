package main

import (
	"fmt"
	"io"
	"net/http"

	eraf "github.com/KaiserWerk/ERAF-Go-SDK"
)

var (
	aesKey = []byte("3d9p8MV0eFe2JeXe6YnD8RNjQ4GdbtNS")
)

func main() {
	http.HandleFunc("/accept", handler)
	http.ListenAndServe(":9000", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		container := eraf.New()
		err := eraf.Unmarshal(r.Body, container)
		if err != nil {
			fmt.Println("could not unmarshal:", err.Error())
			w.WriteHeader(500)
			return
		}
		defer r.Body.Close()
		fmt.Println("unmarshal ok")

		fmt.Println("email:", string(container.GetEmail()))

		err = container.DecryptEverything(container.GetNonce(), aesKey)
		if err != nil {
			fmt.Println("could not decrypt:", err.Error())
			w.WriteHeader(500)
			return
		}
		fmt.Println("decrypt ok")

		fmt.Println("email", string(container.GetEmail()))
		return
	}

	io.WriteString(w, "hello!")
}
