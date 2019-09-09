package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/PuerkitoBio/goquery"
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
	"github.com/urfave/cli"
	"github.com/valyala/fasthttp"
)

type httpResp struct {
	title string
	desc  string
	code  int
}

//////////
//WHOIZ //
//////////

func main() {
	app := cli.NewApp()
	app.Name = "whoiz"
	app.Usage = "because whois is loud af!\n\t example: whoiz domain.com"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "verbose",
			Value: "",
		},
	}

	app.Action = func(c *cli.Context) error {
		domainName := string(c.Args().Get(0))
		fmt.Println("Looking Up... \t ", domainName)

		whoisResult, err := whois.Whois(domainName)
		result, err := whoisparser.Parse(whoisResult)
		printTitle("Domain Reg:")
		if err == nil {
			fmt.Println("\tRegistrant:     " + result.Registrant.Name)
			fmt.Println("\tEmail:          " + result.Registrant.Email)

			fmt.Println("\tRegistrar:      " + result.Registrar.RegistrarName + " [#" + result.Registrar.RegistrarID + "]")
			fmt.Println("\tDomain Status:  " + result.Registrar.DomainStatus)
			fmt.Println("\tCreated Date:   " + result.Registrar.CreatedDate)
			fmt.Println("\tExpiration Date:" + result.Registrar.ExpirationDate)
		} else {
			fmt.Println("\tNo whois information available for " + domainName + " \n")
		}

		printTitle("HTTPS:")
		res := fetchPage(domainName)
		if res.code == 0 {
			fmt.Println("\tPage Title: \t")
			fmt.Println("\tResponse: \t")

		} else {
			fmt.Println("\tPage Title: \t", res.title)
			fmt.Println("\tPage Desc: \t", res.desc)
			fmt.Println("\tResponse: \t", res.code)

		}

		printTitle("Host(s):")
		ips, err := net.LookupIP(domainName)
		if err != nil {
			fmt.Println("[!]\n")
		} else if len(ips) == 0 {
			fmt.Println("No host record found.")
		}
		for _, ip := range ips {
			fmt.Println("\t", ip)
		}

		printTitle("NS record(s):")
		nss, err := net.LookupNS(domainName)
		if err != nil {
			fmt.Println("[!]\n")
		} else if len(nss) == 0 {
			fmt.Println("No NS records found.")
		}
		for _, ns := range nss {
			fmt.Println("\t", ns.Host)
		}

		printTitle("MX record(s):")
		mxs, err := net.LookupMX(domainName)
		if err != nil {
			fmt.Println("[!]\n")
		} else if len(mxs) == 0 {
			fmt.Println("No MX records found.")
		}
		for _, mx := range mxs {
			fmt.Println("\t", mx.Pref, " \t", mx.Host)
		}

		printTitle("TXT record(s):")
		txts, err := net.LookupTXT(domainName)
		if err != nil {
			fmt.Println("[!]\n")
		} else if len(txts) == 0 {
			fmt.Println("No TXT records found.")
		}
		for _, txt := range txts {
			fmt.Println("\t", txt)
		}

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func printTitle(str string) {
	fmt.Println("\n\033[1m" + str + "\033[0m")
}

func fetchPage(domain string) httpResp {
	resp := httpResp{
		title: " - ",
		desc:  " - ",
		code:  0,
	}

	url := string("http://" + domain)
	rc, body, _ := fasthttp.Get(nil, url)
	resp.code = rc
	r := bytes.NewReader(body)
	doc, err := goquery.NewDocumentFromReader(r)
	if err == nil {
		title := doc.Find("title").Text()
		if title != "" {
			resp.title = title
		}
		doc.Find("meta").Each(func(i int, s *goquery.Selection) {
			if name, _ := s.Attr("name"); name == "description" {
				desc, _ := s.Attr("content")
				if desc != "" {
					resp.desc = desc
				}
			}
		})

	}

	return resp
}
