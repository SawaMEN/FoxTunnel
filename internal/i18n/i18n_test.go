package i18n

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestLanguageSelectionAndHelp(t *testing.T) {
	defer SetLanguage("en")
	args, err := SelectLanguage([]string{"client", "--lang", "en", "--help"})
	if err != nil || !slices.Equal(args, []string{"client", "--help"}) || Text("Usage:") != "Usage:" {
		t.Fatalf("%v %v", args, err)
	}
	sentinel := Error("proxy must negotiate h2 ALPN")
	args, err = SelectLanguage([]string{"client", "--help"})
	if err != nil || !slices.Equal(args, []string{"client", "--help"}) {
		t.Fatalf("%v %v", args, err)
	}
	if !strings.Contains(sentinel.Error(), "Прокси") {
		t.Fatal("sentinel language was frozen before selection")
	}
	fs := NewFlagSet("vetroffproxy client")
	fs.String("server", "", Text("remote HTTPS proxy URL"))
	var out bytes.Buffer
	PrintUsage(&out, fs)
	if !strings.Contains(out.String(), "Использование:") || !strings.Contains(out.String(), "URL удалённого") {
		t.Fatal(out.String())
	}
	if _, err := SelectLanguage([]string{"--lang=unknown"}); err == nil {
		t.Fatal("unknown language accepted")
	}
	if _, err := SelectLanguage([]string{"--lang"}); err == nil {
		t.Fatal("missing language accepted")
	}
}
func TestTranslationFormatArguments(t *testing.T) {
	pattern := regexp.MustCompile(`%[+#0 -]*[0-9.]*[a-zA-Z%]`)
	for english, russian := range translations {
		if !slices.Equal(pattern.FindAllString(english, -1), pattern.FindAllString(russian, -1)) {
			t.Errorf("format arguments changed: %q -> %q", english, russian)
		}
	}
}
