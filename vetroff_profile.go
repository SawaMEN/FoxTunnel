package vetroff

import (
    "time"

    "github.com/SawaMEN/VetroffProxy/internal/contract"
    "github.com/SawaMEN/VetroffProxy/internal/profile"
)

// ClientConfigFromLink validates the canonical vetroff:// share profile and
// translates every protocol setting to the embedded SDK. It never includes
// the original link or credentials in parse errors.
func ClientConfigFromLink(link string) (ClientConfig, error) {
    imported, err := profile.Decode(link)
    if err != nil {
        return ClientConfig{}, err
    }
    connectTimeout, err := time.ParseDuration(imported.ConnectTimeout)
    if err != nil {
        return ClientConfig{}, err
    }
    attemptTimeout, err := time.ParseDuration(imported.AttemptTimeout)
    if err != nil {
        return ClientConfig{}, err
    }
    pipeline := 0
    switch imported.Pipeline {
    case "4":
        pipeline = 4
    case "8":
        pipeline = 8
    }
    return ClientConfig{
        RequireProtocolNegotiation: imported.ProtocolPolicy == contract.ProtocolStrict,
        ServerURL:                  imported.Servers[0],
        FallbackServers:            append([]string(nil), imported.Servers[1:]...),
        Credentials:                Credentials{Username: imported.Username, Password: imported.Password},
        TLSBackend:                 imported.TLSBackend,
        Transport:                  imported.Transport,
        ServerName:                 imported.SNI,
        SPKIPin:                    imported.PinSHA256,
        XHTTPPath:                  imported.XHTTPPath,
        XHTTPHost:                  imported.XHTTPHost,
        Balance:                    imported.Balance,
        Padding:                    imported.Padding,
        Bond:                       imported.Bond,
        BondDiscover:               imported.Discover,
        BondPipeline:               pipeline,
        ConnectTimeout:             connectTimeout,
        FallbackAttemptTimeout:     attemptTimeout,
        // The native VPN outbound needs UDP associations for DNS and QUIC.
        // Bond profiles intentionally remain TCP-only (per the CLI contract).
        EnableUDP:                  !imported.Bond,
        UDPStreaming:               !imported.Bond,
    }, nil
}

// NewClientFromLink is the host-side, in-process counterpart to
// vetroff client --link-file. No shell, local port or secret file is needed.
func NewClientFromLink(link string) (*Client, error) {
    config, err := ClientConfigFromLink(link)
    if err != nil {
        return nil, err
    }
    return NewClient(config)
}
