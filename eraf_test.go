package era

import (
	"io"
	"os"
	"reflect"
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

func TestContainer_Payload(t *testing.T) {

	tests := []struct {
		name   string
		container *Container
		want   []byte
	}{
		{name: "empty", container: New(), want: []byte{0, 0, 0}},
		{name: "empty with version", container: func() *Container {
			c := New()
			c.SetVersionMajor(14)
			c.SetVersionMinor(4)
			c.SetVersionPatch(144)
			return c
		}(), want: []byte{14, 4, 144}},
		{name: "with username", container: func() *Container {
			c := New()
			c.SetUsername([]byte("my-cool-username"))
			return c
		}(), want: append([]byte{0, 0, 0}, []byte("my-cool-username")...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.Payload(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Payload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainer_Headers(t *testing.T) {
	c := New()
	if len(c.Headers()) != int(headerSize) {
		t.Fatal("wrong header block size")
	}
}

func TestContainer_Bytes(t *testing.T) {
	tests := []struct {
		name   string
		container *Container
		wantedLength int
	}{
		{name: "empty", container: New(), wantedLength: 45},
		{name: "empty with version", container: func() *Container {
			c := New()
			c.SetVersionMajor(14)
			c.SetVersionMinor(4)
			c.SetVersionPatch(144)
			return c
		}(), wantedLength: 45},
		{name: "with token", container: func() *Container {
			c := New()
			c.SetToken([]byte("123abc456def"))
			return c
		}(), wantedLength: 57},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.Bytes(); len(got) != tt.wantedLength {
				t.Errorf("len(Bytes()) = %v, want %v", len(got), tt.wantedLength)
			}
		})
	}
}

func TestContainer_Read(t *testing.T) {
	type args struct {
		s []byte
	}
	tests := []struct {
		name    string
		container *Container
		args    args
		want    int
		wantErr bool
	}{
		{name: "empty", container: New(), args: args{s: []byte{}}, want: 45, wantErr: false},
		{name: "with email", container: func() *Container {
			c := New()
			c.SetEmail([]byte("my@cool-domain.com"))
			return c
		}(), args: args{s:[]byte{}}, want: 63, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := tt.container.Read(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Read() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainer_PayloadLen(t *testing.T) {
	tests := []struct {
		name   string
		container *Container
		want   int
	}{
		{name: "empty", container: New(), want: 3},
		{name: "with personal identifier", container: func() *Container {
			c := New()
			c.SetPersonalIdentifier([]byte{1, 3, 5, 7, 9})
			return c
		}(), want: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.PayloadLen(); got != tt.want {
				t.Errorf("PayloadLen() = %v, want %v", got, tt.want)
			}
		})
	}
}