// FP-0280 RE2 witness oracle. Reads the base64-safe JSONL produced by
// scripts/dev/dump-regex-witness-menus.php and re-checks every canonical and alternate witness with
// Go's standard regexp package (RE2), the SAME engine nuclei uses. PHP validates witnesses with PCRE;
// PCRE and RE2 can diverge (POSIX classes, \z vs $, …), so a witness that passes PCRE but fails RE2
// would be served to a scanner that never matches it. This oracle catches that class of drift.
//
// It exits non-zero unless every count is zero:
//   - re2-nocompile : a pattern PHP accepted does not compile under RE2;
//   - canonical-miss: the canonical witness does not match its pattern under RE2;
//   - alternate-miss: an alternate witness does not match its pattern under RE2.
//
// nuclei's regex matcher fires on an UNANCHORED search (FindAllString != ∅), so this uses
// MatchString (unanchored), honouring any ^/$ the pattern itself carries.
//
//	php scripts/dev/dump-regex-witness-menus.php /path/to/nuclei-templates/http |
//	  go run scripts/dev/re2-witness-check/main.go
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type row struct {
	P string   `json:"p"`
	C string   `json:"c"`
	A []string `json:"a"`
}

func decode(field, b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("bad base64 in %s: %w", field, err)
	}
	return string(raw), nil
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	// Witnesses/patterns can be long; raise the line cap well beyond the default 64 KiB.
	scanner.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)

	patterns := 0
	canonicalChecks := 0
	alternateChecks := 0
	noCompile := 0
	canonicalMiss := 0
	alternateMiss := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r row
		if err := json.Unmarshal(line, &r); err != nil {
			fmt.Fprintf(os.Stderr, "skip: malformed JSONL line: %v\n", err)
			continue
		}
		pattern, err := decode("p", r.P)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		canonical, err := decode("c", r.C)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		patterns++

		re, err := regexp.Compile(pattern)
		if err != nil {
			noCompile++
			fmt.Fprintf(os.Stderr, "re2-nocompile: %q: %v\n", pattern, err)
			continue
		}

		canonicalChecks++
		if !re.MatchString(canonical) {
			canonicalMiss++
			fmt.Fprintf(os.Stderr, "canonical-miss: %q does not match %q\n", canonical, pattern)
		}
		for _, altB64 := range r.A {
			alt, err := decode("a", altB64)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			alternateChecks++
			if !re.MatchString(alt) {
				alternateMiss++
				fmt.Fprintf(os.Stderr, "alternate-miss: %q does not match %q\n", alt, pattern)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("RE2 audit: patterns=%d canonical-checks=%d alternate-checks=%d | re2-nocompile=%d canonical-miss=%d alternate-miss=%d\n",
		patterns, canonicalChecks, alternateChecks, noCompile, canonicalMiss, alternateMiss)

	if noCompile > 0 || canonicalMiss > 0 || alternateMiss > 0 {
		os.Exit(1)
	}
}
