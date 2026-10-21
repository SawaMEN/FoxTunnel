package udpproto

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestAuditDeclaredFrameWithoutBodyIsTruncated(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0, 10}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("declared body missing: got %v, want unexpected EOF", err)
	}
}
