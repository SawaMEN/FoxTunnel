package main

import (
	"encoding/json"
	h3log "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"
	"strings"
	"testing"
)

func TestCaptureOnlyPeerControlMetadata(t *testing.T) {
	c := &capture{}
	c.RecordEvent(qlog.ParametersSet{Initiator: qlog.InitiatorLocal, InitialMaxData: 999})
	if len(c.result.QUIC.Parameters) != 0 {
		t.Fatal("server parameters confused with peer")
	}
	c.RecordEvent(qlog.ParametersSet{Initiator: qlog.InitiatorRemote, InitialMaxData: 1024})
	c.RecordEvent(h3log.FrameParsed{Frame: h3log.Frame{Frame: h3log.SettingsFrame{MaxFieldSectionSize: -1, Other: map[uint64]uint64{7: 16, 1: 4096}}}})
	if len(c.result.H3.Settings) != 2 || c.result.H3.Settings[0].ID != 1 {
		t.Fatal("settings not normalized")
	}
	c.RecordEvent(h3log.FrameParsed{Frame: h3log.Frame{Frame: h3log.SettingsFrame{MaxFieldSectionSize: 9}}})
	if len(c.result.H3.Settings) != 2 {
		t.Fatal("initial settings overwritten")
	}
	raw, _ := json.Marshal(c.result)
	if strings.Contains(string(raw), "999") || strings.Contains(string(raw), "connection_id") {
		t.Fatal("unselected server or identifier metadata retained")
	}
}
