package era

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func BenchmarkUnmarshal(b *testing.B) {
	var (
		start = New()
		buf bytes.Buffer
		err error
		container = New()
	)

	err = start.Marshal(&buf)
	if err != nil {
		b.Fatal(err.Error())
	}

	for i := 0; i < b.N; i++ {
		err = Unmarshal(&buf, container)
		if err != nil {
			b.Error(err.Error())
		}
	}
}

func BenchmarkMarshal(b *testing.B) {
	var (
		container = New()
		err error
	)
	for i := 0; i < b.N; i++ {
		err = container.Marshal(io.Discard)
		if err != nil {
			b.Error(err.Error())
		}
	}
}

func BenchmarkMarshalToFile(b *testing.B) {
	var (
		container = New()
		err error
	)
	fh, err := os.Create("__test.eraf")
	if err != nil {
		b.Fatal(err.Error())
	}

	defer func() {
		_ = os.Remove("__test.eraf")
	}()
	defer fh.Close()

	for i := 0; i < b.N; i++ {
		err = container.Marshal(fh)
		if err != nil {
			b.Errorf(err.Error())
		}
	}
}
