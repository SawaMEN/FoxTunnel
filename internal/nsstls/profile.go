package nsstls

import "github.com/SawaMEN/FoxTunnel/internal/i18n"

// Firefox158 selects measured NSS groups, key shares and signature preferences.
// It is deliberately not a claim of full Firefox/Necko fingerprint parity.
const Firefox158 = "firefox-158"

func ValidateClientProfile(name string) error {
	if name != "" && name != "default" && name != Firefox158 {
		return i18n.Error("unknown TLS client profile (choose default or firefox-158)")
	}
	return nil
}
