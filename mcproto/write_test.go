package mcproto

import (
	"bytes"
	"io"
	"testing"
)

// readVarIntTest decodes a Minecraft VarInt, mirroring WriteVarInt, so the test
// verifies the wire bytes independently of the writer.
func readVarIntTest(t *testing.T, r io.ByteReader) int32 {
	t.Helper()
	var result int32
	var shift uint
	for {
		b, err := r.ReadByte()
		if err != nil {
			t.Fatalf("readVarInt: %v", err)
		}
		result |= int32(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result
}

func TestWriteLoginDisconnect(t *testing.T) {
	var buf bytes.Buffer
	reason := `{"text":"starting, rejoin shortly"}`
	if err := WriteLoginDisconnect(&buf, reason); err != nil {
		t.Fatalf("WriteLoginDisconnect: %v", err)
	}

	r := bytes.NewReader(buf.Bytes())
	frameLen := readVarIntTest(t, r)
	if int(frameLen) != r.Len() {
		t.Fatalf("declared frame length %d != remaining bytes %d", frameLen, r.Len())
	}
	id := readVarIntTest(t, r)
	if id != PacketIdLoginDisconnect {
		t.Fatalf("packet id = %d, want %d (PacketIdLoginDisconnect)", id, PacketIdLoginDisconnect)
	}
	strLen := readVarIntTest(t, r)
	body := make([]byte, strLen)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != reason {
		t.Fatalf("body = %q, want %q", string(body), reason)
	}
	if r.Len() != 0 {
		t.Fatalf("unexpected trailing bytes: %d", r.Len())
	}
}
