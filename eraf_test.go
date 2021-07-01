package era

import (
	"io"
	"os"
	"testing"
)

func BenchmarkUnmarshalFromFile(b *testing.B) {
	const filename = "__bench_unmarshal_from_file.eraf"
	var (
		start = New()
		err error
		container = New()
	)

	err = start.MarshalToFile(filename)
	if err != nil {
		b.Fatal("could not marshal", err.Error())
	}
	defer os.Remove(filename)

	for i := 0; i < b.N; i++ {
		err = UnmarshalFromFile(filename, container)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}

func BenchmarkUnmarshalBytes(b *testing.B) {
	var (
		start = New()
		container = New()
		err error
	)
	//fmt.Println("bytes:", start.Bytes())
	//buf := bytes.NewBuffer(start.Bytes())

	for i := 0; i < b.N; i++ {
		err = UnmarshalBytes(start.Bytes(), container)
		if err != nil {
			b.Fatal(err.Error())
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
	const filename = "__bench_marshal_to_file.eraf"
	var (
		container = New()
		err error
	)
	fh, err := os.Create(filename)
	if err != nil {
		b.Fatal(err.Error())
	}

	defer func() {
		_ = os.Remove(filename)
	}()
	defer fh.Close()

	for i := 0; i < b.N; i++ {
		err = container.Marshal(fh)
		if err != nil {
			b.Errorf(err.Error())
		}
	}
}
