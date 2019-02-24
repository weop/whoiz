package main

import (
  "fmt"
  "strings"
  "net"
  "net/http"
  "crypto/tls"
  "log"
  "io/ioutil"
  "os"
  "github.com/urfave/cli"
  "github.com/likexian/whois-go"
  "github.com/likexian/whois-parser-go"
)

//////////
//WHOIZ //
//////////

func main() {
  app := cli.NewApp()
  app.Name = "whoiz"
  app.Usage = "because whois is loud af!\n\t example: whoiz domain.com"

  app.Flags = []cli.Flag {
    cli.StringFlag{
      Name: "verbose",
      Value: "",
    },
  }

  app.Action = func(c *cli.Context) error {
    domainName := string(c.Args().Get(0))


    fmt.Printf("\nDomain Reg:")
	whoisResult, err := whois.Whois(domainName)
	result, err := whoisparser.Parse(whoisResult)
	if err == nil {
	    fmt.Printf("\n\tRegistrant:     "+result.Registrant.Name)
	    fmt.Printf("\n\tEmail:          "+result.Registrant.Email)

	    fmt.Printf("\n\tDomain Status:  "+result.Registrar.DomainStatus)
	    fmt.Printf("\n\tCreated Date:   "+result.Registrar.CreatedDate)
	    fmt.Printf("\n\tExpiration Date:"+result.Registrar.ExpirationDate)
	}else{
    	fmt.Printf("\n\tNo whois information available for "+domainName+" \n")
	}

    fmt.Printf("\nHTTPS:\n")
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    res, err := http.Get("https://"+domainName)
   
    if err != nil {
		fmt.Printf("\tReply: Invalid Response!\n")
    }else{
	    if res.StatusCode >= 200 && res.StatusCode <= 299 {
	        fmt.Printf("\tReply: Valid [%d]\n", res.StatusCode)
	    } else {
	        fmt.Printf("\tReply: Invalid [%d]\n", res.StatusCode)
	    }    	
	    //Capture Page Title
	    htmlBytes, _ := ioutil.ReadAll(res.Body)
	    htmlStr := string(htmlBytes)
	    domStart := strings.Index(htmlStr, "<title>") //get title
	    if domStart == -1 {
			 fmt.Printf("\tNo Page Title Found.\n")
	    }else{
		    domStart += 7 //skips <title>
		    domEnd := strings.Index(htmlStr, "</title>")  //get ending
		    if domEnd == -1 {
				 fmt.Printf("\tError in Title.\n")
		    }else{
				siteTitle := []byte(htmlStr[domStart:domEnd])
				fmt.Printf("\tPage Title: %s\n", siteTitle)	    	
		    }
	    }
    }



    fmt.Printf("\nHost(s):\n")
    ips, err := net.LookupIP(domainName)
    if err != nil {
		fmt.Printf("[!]\n")
	}else if len(ips) == 0 {
		fmt.Printf("No host record found.")
	}
    for _, ip := range ips {
		fmt.Printf("\t%s\n", ip.String())
	}

    fmt.Printf("\nNS record(s):\n")
    nss, err := net.LookupNS(domainName)
	if err != nil {
		fmt.Printf("[!]\n")
	} else if len(nss) == 0 {
		fmt.Printf("No NS records found.")
	}
	for _, ns := range nss {
		fmt.Printf("\t%s\n", ns.Host)
	}


    fmt.Printf("\nMX record(s):\n")
    mxs, err := net.LookupMX(domainName)
	if err != nil {
		fmt.Printf("[!]\n")
	}else if len(mxs) == 0 {
		fmt.Printf("No MX records found.")
	}
    for _, mx := range mxs {
		fmt.Printf("\t%s %v\n", mx.Host, mx.Pref)
	}
			

    fmt.Printf("\nTXT record(s):\n")
    txts, err := net.LookupTXT(domainName)
	if err != nil {
		fmt.Printf("[!]\n")
	}else if len(txts) == 0 {
		fmt.Printf("No TXT records found.")
	}
	for _, txt := range txts {
		fmt.Printf("%s\n", txt)
	}

    return nil
  }

  err := app.Run(os.Args)
  if err != nil {
    log.Fatal(err)
  }
}
