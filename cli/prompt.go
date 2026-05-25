package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// isTTY reports whether f is connected to a real terminal. Uses termios via
// golang.org/x/term — checking only the file's mode incorrectly returns true
// for /dev/null and other character devices.
func isTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// yesNo asks the user a Y/N question. Empty input returns defaultYes. Any
// unexpected input also returns defaultYes (forgiving rather than re-prompting).
func yesNo(r io.Reader, w io.Writer, question string, defaultYes bool) (bool, error) {
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	if _, err := fmt.Fprintf(w, "%s %s: ", question, suffix); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return defaultYes, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return defaultYes, nil
	}
}

// promptWithDefault asks for a single value; empty input returns def.
func promptWithDefault(r io.Reader, w io.Writer, label, def string) (string, error) {
	if _, err := fmt.Fprintf(w, "  %s [%s]: ", label, def); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}
