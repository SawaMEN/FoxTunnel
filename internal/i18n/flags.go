package i18n

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// SelectLanguage removes the common flag before subcommand parsing. Russian is
// the CLI default; protocol names, flag names and machine-readable output stay stable.
func SelectLanguage(args []string) ([]string, error) {
	language := "ru"
	result := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--lang" || arg == "-lang" {
			if i+1 == len(args) {
				_ = SetLanguage("ru")
				return nil, Error("--lang requires ru or en")
			}
			i++
			language = args[i]
		} else if strings.HasPrefix(arg, "--lang=") || strings.HasPrefix(arg, "-lang=") {
			language = strings.SplitN(arg, "=", 2)[1]
		} else {
			result = append(result, arg)
		}
	}
	_ = SetLanguage("ru")
	if err := SetLanguage(language); err != nil {
		return nil, err
	}
	return result, nil
}

func NewFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	language := "ru"
	if !russian.Load() {
		language = "en"
	}
	fs.String("lang", language, Text("Language: ru (default), en"))
	fs.Usage = func() { PrintUsage(os.Stderr, fs) }
	return fs
}
func PrintUsage(out io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(out, Text("Usage:"), fs.Name(), "[--lang ru|en]")
	fmt.Fprintln(out, Text("Options:"))
	fs.VisitAll(func(f *flag.Flag) {
		name, help := flag.UnquoteUsage(f)
		fmt.Fprintf(out, "  --%s", f.Name)
		if name != "" {
			fmt.Fprint(out, " ", name)
		}
		fmt.Fprintln(out, "\n      ", help)
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
			fmt.Fprintln(out, "      ", Text("default")+":", f.DefValue)
		}
	})
}
func Parse(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, Text("invalid arguments: %v")+"\n", err)
		fs.Usage()
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, Text("invalid arguments: %v")+"\n", fs.Args())
		fs.Usage()
		os.Exit(2)
	}
}
