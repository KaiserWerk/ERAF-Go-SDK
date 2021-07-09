package era

import (
	"bytes"
	"io"
	"os"
	"reflect"
	"testing"
)

func TestContainer_New(t *testing.T) {
	var (
		data interface{} = New()
	)

	if _, ok := data.(*Container); !ok {
		t.Errorf("Expected new *Container from New()")
	}
}

func TestContainer_GetVersionMajor(t *testing.T) {
	var (
		c             = New()
		expected byte = 150
	)
	c.SetVersionMajor(expected)

	if c.GetVersionMajor() != expected {
		t.Errorf("Expected version major %d, got %d", expected, c.GetVersionMajor())
	}
}

func TestContainer_SetVersionMajor(t *testing.T) {
	var (
		c             = New()
		expected byte = 150
	)
	c.SetVersionMajor(expected)

	if c.GetVersionMajor() != expected {
		t.Errorf("Expected version major %d, got %d", expected, c.GetVersionMajor())
	}
}

func TestContainer_GetVersionMinor(t *testing.T) {
	var (
		c             = New()
		expected byte = 17
	)
	c.SetVersionMinor(expected)

	if c.GetVersionMinor() != expected {
		t.Errorf("Expected version minor %d, got %d", expected, c.GetVersionMinor())
	}
}

func TestContainer_SetVersionMinor(t *testing.T) {
	var (
		c             = New()
		expected byte = 17
	)
	c.SetVersionMinor(expected)

	if c.GetVersionMinor() != expected {
		t.Errorf("Expected version minor %d, got %d", expected, c.GetVersionMinor())
	}
}

func TestContainer_GetVersionPatch(t *testing.T) {
	var (
		c             = New()
		expected byte = 4
	)
	c.SetVersionPatch(expected)

	if c.GetVersionPatch() != expected {
		t.Errorf("Expected version patch %d, got %d", expected, c.GetVersionPatch())
	}
}

func TestContainer_SetVersionPatch(t *testing.T) {
	var (
		c             = New()
		expected byte = 4
	)
	c.SetVersionPatch(expected)

	if c.GetVersionPatch() != expected {
		t.Errorf("Expected version patch %d, got %d", expected, c.GetVersionPatch())
	}
}

func TestContainer_GetNonce(t *testing.T) {
	var (
		expected = []byte{1, 2, 3, 4, 5}
		c        = New().SetNonce(expected)
	)

	if !bytes.Equal(c.GetNonce(), expected) {
		t.Errorf("Expected nonce %#v, got %#v", expected, c.GetNonce())
	}
}

func TestContainer_SetNonce(t *testing.T) {
	var (
		expected = []byte{1, 2, 3, 4, 5}
		c        = New().SetNonce(expected)
	)

	if !bytes.Equal(c.GetNonce(), expected) {
		t.Errorf("Expected %#v, got %#v", expected, c.GetNonce())
	}
}

func TestContainer_GetTag(t *testing.T) {
	var (
		expected = []byte{6, 7, 8, 9, 10}
		c        = New().SetTag(expected)
	)

	if !bytes.Equal(c.GetTag(), expected) {
		t.Errorf("Expected tag %#v, got %#v", expected, c.GetTag())
	}
}

func TestContainer_SetTag(t *testing.T) {
	var (
		expected = []byte{6, 7, 8, 9, 10}
		c        = New().SetTag(expected)
	)

	if !bytes.Equal(c.GetTag(), expected) {
		t.Errorf("Expected tag %#v, got %#v", expected, c.GetTag())
	}
}

func TestContainer_GetIdentifier(t *testing.T) {
	var (
		expected = []byte{75, 180, 50, 1}
		c        = New().SetIdentifier(expected)
	)

	if !bytes.Equal(c.GetIdentifier(), expected) {
		t.Errorf("Expected identifier %#v, got %#v", expected, c.GetIdentifier())
	}
}

func TestContainer_SetIdentifier(t *testing.T) {
	var (
		expected = []byte{75, 180, 50, 1}
		c        = New().SetIdentifier(expected)
	)

	if !bytes.Equal(c.GetIdentifier(), expected) {
		t.Errorf("Expected identifier %#v, got %#v", expected, c.GetIdentifier())
	}
}

func TestContainer_Payload(t *testing.T) {

	tests := []struct {
		name      string
		container *Container
		want      []byte
	}{
		{name: "empty", container: New(), want: []byte{0, 0, 0}},
		{name: "empty with version", container: func() *Container {
			return New().SetVersionMajor(14).
				SetVersionMinor(4).
				SetVersionPatch(144)
		}(), want: []byte{14, 4, 144}},
		{name: "with username", container: func() *Container {
			return New().SetUsername([]byte("my-cool-username"))
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

//func TestContainer_Read(t *testing.T) {
//	type args struct {
//		s []byte
//	}
//	tests := []struct {
//		name      string
//		container *Container
//		args      args
//		want      int
//		wantErr   bool
//	}{
//		{name: "empty", container: New(), args: args{s: make([]byte, 0, 100)}, want: int(headerSize) + 3, wantErr: true}, // headerSize + version bytes
//		{name: "with email", container: func() *Container {
//			return New().SetEmail([]byte("my@cool-domain.com"))
//		}(), args: args{s: make([]byte, 0, 100)}, want: 67, wantErr: true},  // headerSize + version bytes + email
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//
//			got, err := tt.container.Read(tt.args.s)
//			if (err != nil) != tt.wantErr {
//				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
//				return
//			}
//			if got != tt.want {
//				t.Errorf("Read() got = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}

func TestContainer_PayloadLen(t *testing.T) {
	tests := []struct {
		name      string
		container *Container
		want      int
	}{
		{name: "empty", container: New(), want: 3},
		{name: "with personal identifier", container: func() *Container {
			return New().SetIdentifier([]byte{1, 3, 5, 7, 9})
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

func TestContainer_HeaderLen(t *testing.T) {
	tests := []struct {
		name      string
		container *Container
		want      int
	}{
		{name: "normal", container: New(), want: int(headerSize)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.container.HeaderLen(); got != tt.want {
				t.Errorf("HeaderLen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkUnmarshalFromFile(b *testing.B) {
	const filename = "__bench_unmarshal_from_file.eraf"
	var (
		start     = New()
		err       error
		container = New()
	)

	err = start.MarshalToFile(filename, 0744)
	if err != nil {
		b.Fatal("could not marshal", err.Error())
	}
	defer func() {
		_ = os.Remove(filename)
	}()

	for i := 0; i < b.N; i++ {
		err = UnmarshalFromFile(filename, container)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}

func BenchmarkUnmarshalBytes(b *testing.B) {
	var (
		container = New()
		s         = New().MarshalBytes()
		err       error
	)

	for i := 0; i < b.N; i++ {
		err = UnmarshalBytes(s, container)
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}

func BenchmarkMarshal(b *testing.B) {
	var (
		container = New()
		err       error
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
		err       error
	)
	fh, err := os.Create(filename)
	if err != nil {
		b.Fatal(err.Error())
	}

	defer func() {
		_ = os.Remove(filename)
	}()
	defer func() {
		_ = fh.Close()
	}()

	for i := 0; i < b.N; i++ {
		err = container.Marshal(fh)
		if err != nil {
			b.Errorf(err.Error())
		}
	}
}
