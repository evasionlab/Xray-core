package buf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type nilSlotReader struct {
	mb MultiBuffer
}

func (r *nilSlotReader) ReadMultiBuffer() (MultiBuffer, error) {
	mb := r.mb
	r.mb = nil
	return mb, io.EOF
}

type nilSlotCounter int64

func (c *nilSlotCounter) Value() int64 { return int64(*c) }
func (c *nilSlotCounter) Set(v int64) int64 {
	old := *c
	*c = nilSlotCounter(v)
	return int64(old)
}

func (c *nilSlotCounter) Add(v int64) int64 {
	*c += nilSlotCounter(v)
	return int64(*c)
}

func TestBufferToBytesWriterNilSlots(t *testing.T) {
	for _, positions := range [][]int{{0}, {1}, {2}, {0, 1, 3}, {0, 1, 2, 3}} {
		t.Run(fmt.Sprint(positions), func(t *testing.T) {
			mb := MultiBuffer{New(), New()}
			_, _ = mb[0].Write([]byte("first"))
			_, _ = mb[1].Write([]byte("second"))
			live := append(MultiBuffer(nil), mb...)
			for _, position := range positions {
				mb = append(mb, nil)
				copy(mb[position+1:], mb[position:])
				mb[position] = nil
			}
			var output bytes.Buffer
			var counter nilSlotCounter
			writer := &BufferToBytesWriter{Writer: &output, counter: &counter}
			if err := Copy(&nilSlotReader{mb: mb}, writer); err != nil {
				t.Fatal(err)
			}
			if output.String() != "firstsecond" || counter.Value() != 11 {
				t.Fatalf("output=%q counter=%d", output.String(), counter.Value())
			}
			for _, b := range live {
				if b.v != nil {
					t.Fatal("owned buffer was not released")
				}
			}
			for _, b := range mb {
				if b != nil {
					t.Fatal("ownership slot was not cleared")
				}
			}
			// Reusing the writer must not retain or resend the previous iovec.
			if err := writer.WriteMultiBuffer(MultiBuffer{nil, FromBytes([]byte("next")), nil}); err != nil {
				t.Fatal(err)
			}
			if output.String() != "firstsecondnext" || counter.Value() != 15 {
				t.Fatalf("reuse output=%q counter=%d", output.String(), counter.Value())
			}
		})
	}
}

func TestBufferToBytesWriterEmptyReaderMerge(t *testing.T) {
	// SingleReader returns {nil} at EOF. MergeMulti must transfer that batch
	// without dropping subsequent data or changing its ownership semantics.
	empty, err := (&SingleReader{Reader: bytes.NewReader(nil)}).ReadMultiBuffer()
	if err != io.EOF || len(empty) != 1 || empty[0] != nil {
		t.Fatalf("unexpected empty read: %v, %v", empty, err)
	}
	mb, source := MergeMulti(empty, MultiBuffer{FromBytes([]byte("payload"))})
	if len(source) != 0 {
		t.Fatal("merge did not transfer source ownership")
	}
	var output bytes.Buffer
	if err := Copy(&nilSlotReader{mb: mb}, &BufferToBytesWriter{Writer: &output}); err != nil || output.String() != "payload" {
		t.Fatalf("merged copy output=%q err=%v", output.String(), err)
	}
}

func TestBufferToBytesWriterOnlyNilSlots(t *testing.T) {
	for _, mb := range []MultiBuffer{nil, {nil}, {nil, nil}} {
		// No underlying writer is necessary: an empty batch must not write.
		if err := (&BufferToBytesWriter{}).WriteMultiBuffer(mb); err != nil {
			t.Fatal(err)
		}
	}
}

type nilSlotFailWriter struct{ err error }

func (w nilSlotFailWriter) Write(p []byte) (int, error) {
	return 1, w.err
}

func TestBufferToBytesWriterNilSlotsWriteFailure(t *testing.T) {
	failure := errors.New("write failed")
	first, second := New(), New()
	_, _ = first.Write([]byte("abc"))
	_, _ = second.Write([]byte("def"))
	mb := MultiBuffer{nil, first, nil, second, nil}
	var counter nilSlotCounter
	w := &BufferToBytesWriter{Writer: nilSlotFailWriter{failure}, counter: &counter}
	err := Copy(&nilSlotReader{mb: mb}, w)
	if !IsWriteError(err) || !errors.Is(err, failure) || counter.Value() != 1 {
		t.Fatalf("err=%v counter=%d", err, counter.Value())
	}
	if first.v != nil || second.v != nil {
		t.Fatal("write failure leaked owned buffers")
	}
}

func TestBufferToBytesWriterNilSlotsTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		data, _ := io.ReadAll(conn)
		result <- data
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	err = Copy(&nilSlotReader{mb: MultiBuffer{FromBytes([]byte("one")), nil, FromBytes([]byte("two"))}}, NewWriter(conn))
	_ = conn.Close()
	if err != nil || string(<-result) != "onetwo" {
		t.Fatalf("TCP copy failed: %v", err)
	}
}
