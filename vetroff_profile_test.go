package vetroff_test

import (
    "strings"
    "testing"
    "time"

    vetroff "github.com/SawaMEN/VetroffProxy"
    "github.com/SawaMEN/VetroffProxy/internal/profile"
)

func TestClientConfigFromLinkPreservesTransportAndSecrets(t *testing.T) {
    link, err := profile.Encode(profile.Config{
        Version: 1,
        Servers: []string{"https://edge.example.com", "https://backup.example.com"},
        Username: "alice",
        Password: "private-credential",
        Transport: "xhttp-stream-one",
        XHTTPPath: "/secret-path",
        XHTTPHost: "site.example.com",
        TLSBackend: "go",
        SNI: "edge.example.com",
        Balance: "round-robin",
        Padding: true,
        ConnectTimeout: "16s",
        AttemptTimeout: "4s",
    })
    if err != nil {
        t.Fatal(err)
    }
    parsed, err := vetroff.ClientConfigFromLink(link)
    if err != nil {
        t.Fatal(err)
    }
    if parsed.ServerURL != "https://edge.example.com" || len(parsed.FallbackServers) != 1 ||
        parsed.FallbackServers[0] != "https://backup.example.com" ||
        parsed.Credentials.Password != "private-credential" ||
        parsed.Transport != "xhttp-stream-one" || parsed.XHTTPPath != "/secret-path" ||
        parsed.XHTTPHost != "site.example.com" || parsed.Balance != "round-robin" ||
        !parsed.EnableUDP || !parsed.UDPStreaming || parsed.ConnectTimeout != 16*time.Second ||
        parsed.FallbackAttemptTimeout != 4*time.Second {
        t.Fatal("decoded embedded-client settings do not match share profile")
    }
}

func TestClientConfigFromLinkPreservesBond(t *testing.T) {
    link, err := profile.Encode(profile.Config{
        Version: 1, Servers: []string{"https://a.example.com", "https://b.example.com"},
        Username: "alice", Password: "secret", Bond: true, Pipeline: "8",
    })
    if err != nil { t.Fatal(err) }
    cfg, err := vetroff.ClientConfigFromLink(link)
    if err != nil { t.Fatal(err) }
    if !cfg.Bond || cfg.BondPipeline != 8 || cfg.EnableUDP {
        t.Fatal("bond profile was silently changed")
    }
}

func TestClientConfigFromLinkNeverLeaksSecretsOnFailure(t *testing.T) {
    const secret = "private-password"
    _, err := vetroff.ClientConfigFromLink("vetroff://" + secret)
    if err == nil || strings.Contains(err.Error(), secret) {
        t.Fatal("invalid share link accepted or leaked")
    }
}
