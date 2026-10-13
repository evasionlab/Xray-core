package freedom

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func fragmentConfig() *Fragment {
	return &Fragment{PacketsFrom: 0, PacketsTo: 1, LengthMin: 3, LengthMax: 3}
}

func tlsRecord(payload []byte) []byte {
	return append([]byte{22, 3, 3, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func checkFragmented(t *testing.T, output, payload []byte, maxFragments int) {
	t.Helper()
	var recovered []byte
	count := 0
	for len(output) != 0 {
		if len(output) < 5 || !bytes.Equal(output[:3], []byte{22, 3, 3}) {
			t.Fatalf("invalid record header: %x", output)
		}
		n := int(output[3])<<8 | int(output[4])
		if n == 0 || n > len(output)-5 {
			t.Fatalf("invalid record length: %d", n)
		}
		recovered = append(recovered, output[5:5+n]...)
		output = output[5+n:]
		count++
	}
	if !bytes.Equal(recovered, payload) || count != maxFragments {
		t.Fatalf("payload = %x, fragments = %d, want %x / %d", recovered, count, payload, maxFragments)
	}
}

func TestFragmentWriterTLSHelloAllBoundaries(t *testing.T) {
	payload := []byte("client hello with server name")
	record := tlsRecord(payload)
	var expected bytes.Buffer
	whole := &FragmentWriter{fragment: fragmentConfig(), writer: &expected}
	if n, err := whole.Write(record); n != len(record) || err != nil {
		t.Fatalf("whole record: %d, %v", n, err)
	}
	checkFragmented(t, expected.Bytes(), payload, (len(payload)+2)/3)
	for split := 1; split < len(record); split++ {
		var output bytes.Buffer
		f := &FragmentWriter{fragment: fragmentConfig(), writer: &output}
		for _, part := range [][]byte{record[:split], nil, record[split:]} {
			if n, err := f.Write(part); n != len(part) || err != nil {
				t.Fatalf("split %d: %d, %v", split, n, err)
			}
		}
		if !bytes.Equal(output.Bytes(), expected.Bytes()) {
			t.Fatalf("split %d differs: %x", split, output.Bytes())
		}
	}
}

func TestFragmentWriterTLSHelloSequentialWriter(t *testing.T) {
	payload := []byte("multi buffer client hello")
	record := tlsRecord(payload)
	var output bytes.Buffer
	f := &FragmentWriter{fragment: fragmentConfig(), writer: &output}
	writer := buf.NewWriter(f)
	var mb buf.MultiBuffer
	for _, b := range record {
		mb = append(mb, buf.FromBytes([]byte{b}))
	}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	checkFragmented(t, output.Bytes(), payload, (len(payload)+2)/3)
}

func TestFragmentWriterTLSHelloTrailingBytes(t *testing.T) {
	payload := []byte("hello")
	record := tlsRecord(payload)
	trailing := tlsRecord([]byte("second record"))
	for _, split := range []int{0, 2, 7} {
		var output bytes.Buffer
		f := &FragmentWriter{fragment: fragmentConfig(), writer: &output}
		if n, err := f.Write(record[:split]); n != split || err != nil {
			t.Fatal(n, err)
		}
		last := append(append([]byte{}, record[split:]...), trailing...)
		if n, err := f.Write(last); n != len(last) || err != nil {
			t.Fatal(n, err)
		}
		end := len(output.Bytes()) - len(trailing)
		checkFragmented(t, output.Bytes()[:end], payload, 2)
		if !bytes.Equal(output.Bytes()[end:], trailing) {
			t.Fatal("trailing record changed")
		}
		if n, err := f.Write(trailing); n != len(trailing) || err != nil || !bytes.HasSuffix(output.Bytes(), append(trailing, trailing...)) {
			t.Fatal("subsequent write changed", n, err)
		}
	}
}

func TestFragmentWriterTLSHelloPassthrough(t *testing.T) {
	inputs := [][]byte{
		[]byte("GET / HTTP/1.1\r\n"),
		{23, 3, 3, 0, 2, 1, 2},
		{22, 2, 3, 0, 2, 1, 2},
		{22, 3, 5, 0, 2, 1, 2},
		{22, 3, 3, 0, 0},
		{22, 3, 3, 0x40, 1, 1},
	}
	for _, input := range inputs {
		for split := 1; split < len(input); split++ {
			var output bytes.Buffer
			f := &FragmentWriter{fragment: fragmentConfig(), writer: &output}
			for _, part := range [][]byte{nil, input[:split], input[split:]} {
				if n, err := f.Write(part); n != len(part) || err != nil {
					t.Fatal(n, err)
				}
			}
			if !bytes.Equal(input, output.Bytes()) || len(f.tlsPending) != 0 {
				t.Fatalf("passthrough %x became %x", input, output.Bytes())
			}
		}
	}
}

func TestFragmentWriterTLSHelloMaxRecordAndSplit(t *testing.T) {
	payload := bytes.Repeat([]byte{1}, maxTLSHandshakeRecord)
	record := tlsRecord(payload)
	var output bytes.Buffer
	config := fragmentConfig()
	config.MaxSplitMin, config.MaxSplitMax = 2, 2
	f := &FragmentWriter{fragment: config, writer: &output}
	for i, b := range record {
		if n, err := f.Write([]byte{b}); n != 1 || err != nil {
			t.Fatal(n, err)
		}
		if cap(f.tlsPending) > 5+maxTLSHandshakeRecord {
			t.Fatalf("unbounded pending allocation at %d", i)
		}
	}
	checkFragmented(t, output.Bytes(), payload, 2)
}

func TestFragmentWriterTLSHelloFlushIncomplete(t *testing.T) {
	for _, size := range []int{1, 4, 7} {
		var output bytes.Buffer
		f := &FragmentWriter{fragment: fragmentConfig(), writer: &output}
		partial := tlsRecord([]byte("incomplete"))[:size]
		if n, err := f.Write(partial); n != size || err != nil || output.Len() != 0 {
			t.Fatal("buffering", n, err)
		}
		if err := f.Flush(); err != nil || !bytes.Equal(output.Bytes(), partial) || f.tlsPending != nil {
			t.Fatal("flush", err)
		}
		if err := f.Flush(); err != nil || output.Len() != size {
			t.Fatal("duplicate flush", err)
		}
	}
}

type failingFragmentSink struct {
	err error
}

func (w failingFragmentSink) Write(b []byte) (int, error) {
	return 0, w.err
}

func TestFragmentWriterTLSHelloErrors(t *testing.T) {
	failure := errors.New("write failed")
	for _, interval := range []uint64{0, 1} {
		config := fragmentConfig()
		config.IntervalMin, config.IntervalMax = interval, interval
		f := &FragmentWriter{fragment: config, writer: failingFragmentSink{err: failure}}
		record := tlsRecord([]byte("hello"))
		if n, err := f.Write(record[:7]); n != 7 || err != nil {
			t.Fatal("buffering", n, err)
		}
		if n, err := f.Write(record[7:]); n != 0 || !errors.Is(err, failure) || f.tlsPending != nil {
			t.Fatal("fragment write error", n, err)
		}
	}
	f := &FragmentWriter{fragment: fragmentConfig(), writer: failingFragmentSink{}}
	if _, err := f.Write(tlsRecord([]byte("hello"))); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short write", err)
	}
	f = &FragmentWriter{fragment: fragmentConfig(), writer: failingFragmentSink{err: failure}}
	if _, err := f.Write([]byte{22}); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(); !errors.Is(err, failure) {
		t.Fatal("flush error", err)
	}
}

type fragmentRequestReader struct {
	payload []byte
	err     error
}

func (r *fragmentRequestReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	payload := r.payload
	r.payload = nil
	if len(payload) == 0 {
		return nil, r.err
	}
	return buf.MultiBuffer{buf.FromBytes(payload)}, r.err
}

func TestFragmentWriterTLSHelloRequestEOFAndAbort(t *testing.T) {
	failure := errors.New("request read failed")
	for _, end := range []error{io.EOF, failure} {
		var output bytes.Buffer
		partial := tlsRecord([]byte("incomplete"))[:7]
		f := &FragmentWriter{fragment: fragmentConfig(), writer: &output}
		err := buf.Copy(&fragmentRequestReader{payload: partial, err: end}, buf.NewWriter(f))
		// Same lifecycle as the Freedom request: only a successful EOF flushes.
		if err == nil {
			err = f.Flush()
		}
		if end == io.EOF {
			if err != nil || !bytes.Equal(output.Bytes(), partial) {
				t.Fatal("EOF lost pending bytes", err)
			}
		} else if !errors.Is(err, failure) || output.Len() != 0 {
			t.Fatal("failed request wrote pending bytes", err)
		}
	}
}

func TestFragmentWriterPacketRangeUnchanged(t *testing.T) {
	var output bytes.Buffer
	config := fragmentConfig()
	config.PacketsFrom, config.PacketsTo = 2, 2
	f := &FragmentWriter{fragment: config, writer: &output}
	payload := []byte("ordinary packets")
	for i := 0; i < 3; i++ {
		if n, err := f.Write(payload); n != len(payload) || err != nil {
			t.Fatal(n, err)
		}
	}
	if f.count != 3 || f.tlsPending != nil || !bytes.Equal(output.Bytes(), bytes.Repeat(payload, 3)) {
		t.Fatal("packet range behavior changed")
	}
}
