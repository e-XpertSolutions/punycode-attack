// top-vulnerable-domains: a tool for extracting the list of domains that are
// vulnerable to the attack recently exposed by the security expert Xudong
// Zheng.
//
// More information can be found in our blog article available at the following
// address:
//    https://www.e-xpertsolutions.com/undetectable-punycode-phishing-attack/
//
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// easily exploitable characters
var alphabet = map[rune]struct{}{
	'a': struct{}{},
	'p': struct{}{},
	'l': struct{}{},
	'e': struct{}{},
	'c': struct{}{},
	'x': struct{}{},
	's': struct{}{},
	'y': struct{}{},
	'j': struct{}{},
	'i': struct{}{},
	'h': struct{}{},
	'o': struct{}{},
	'-': struct{}{},
}

func splitDomain(domainName string) (subdomain, domain, tld string) {
	if domainName == "" {
		return
	}
	if publicSuffix, _ := publicsuffix.PublicSuffix(domainName); publicSuffix == domainName {
		segments := strings.Split(domainName, ".")
		switch l := len(segments); l {
		case 1:
			domain = segments[0]
		case 2:
			domain = segments[0]
			tld = segments[1]
		default:
			subdomain = strings.Join(segments[:l-2], ".")
			domain = segments[l-2]
			tld = segments[l-1]
		}
		return
	} else if publicSuffix != "" {
		tld = "." + publicSuffix
	}
	segments := strings.Split(strings.TrimSuffix(domainName, tld), ".")
	switch l := len(segments); l {
	case 1:
		domain = segments[0]
	default:
		subdomain = strings.Join(segments[:l-1], ".")
		domain = segments[l-1]
	}
	return
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s [FILE] \n", filepath.Base(os.Args[0]))
	fmt.Fprintln(os.Stderr, `
This tool extracts the list of domains that are vulnerable to the attack
recently exposed by the security expert Xudong Zheng.

FILE is expected to be the path to a list of domains previously downloaded
using the script https://gist.github.com/chilts/7229605

More information can be found in our blog article available at the following
address:

https://www.e-xpertsolutions.com/undetectable-punycode-phishing-attack/

`)
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() < 1 {
		log.Fatal("missing file in argument")
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		log.Fatal("failed to open input file: ", err)
	}
	defer f.Close()

	br := bufio.NewReader(f)

	var (
		list []string
		pos  int
	)
rdloop:
	for {
		pos++

		line, err := br.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("failed to read line #%d: %v", err)
			}
			break
		}

		line = strings.TrimPrefix(line, "[ ")
		line = strings.TrimSuffix(line, " ]\n")

		records := strings.Split(line, ", ")
		if len(records) != 2 {
			continue
		}

		host := strings.Trim(records[1], "'")
		_, domain, _ := splitDomain(host)

		for _, ch := range domain {
			if _, ok := alphabet[ch]; !ok {
				continue rdloop
			}
		}

		list = append(list, host)
	}

	fmt.Printf("Vulnerable domains (%d):\n\n", len(list))
	fmt.Println(strings.Join(list, "\n"))
}
