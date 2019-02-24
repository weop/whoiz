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
  "bytes"
  "os/exec"
  "github.com/urfave/cli"
  "golang.org/x/net/publicsuffix"
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

	tldomain, _ := publicsuffix.EffectiveTLDPlusOne(domainName)
	if ( len(tldomain) <= 1 ){
		println ("Invalid domain provided!");
		return nil; //Lets not proceed without a valid TLD
	}
	

    cmd := exec.Command("bash","-c","whois "+tldomain+"| head -n10")
    //todo is there a golib for whois?
    cmdOutput := &bytes.Buffer{}
    cmd.Stdout = cmdOutput

    err := cmd.Run()
    if err != nil {
     os.Stderr.WriteString(err.Error())
    }
    if bytes.Contains(cmdOutput.Bytes(), []byte("No whois")) {
	   	println("No whois server known for the provided domain name!");
		return nil;
	}
    fmt.Printf("\nDomain Reg:\n")
    fmt.Print(string(cmdOutput.Bytes()))

    fmt.Printf("\nHTTPS:\n")
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    res, err := http.Get("https://"+domainName)
   
    if err != nil {
		fmt.Printf("   Reply: Invalid Response!\n")
    }else{
	    if res.StatusCode >= 200 && res.StatusCode <= 299 {
	        fmt.Printf("   Reply: Valid [%d]\n", res.StatusCode)
	    } else {
	        fmt.Printf("   Reply: Invalid [%d]\n", res.StatusCode)
	    }    	
	    //Capture Page Title
	    htmlBytes, _ := ioutil.ReadAll(res.Body)
	    htmlStr := string(htmlBytes)
	    domStart := strings.Index(htmlStr, "<title>") //get title
	    if domStart == -1 {
			 fmt.Printf("   No Page Title Found.\n")
	    }else{
		    domStart += 7 //skips <title>
		    domEnd := strings.Index(htmlStr, "</title>")  //get ending
		    if domEnd == -1 {
				 fmt.Printf("   Error in Title.\n")
		    }else{
				siteTitle := []byte(htmlStr[domStart:domEnd])
				fmt.Printf("   Page Title: %s\n", siteTitle)	    	
		    }
	    }
    }



    fmt.Printf("\nHost(s):\n")
    ips, err := net.LookupIP(domainName)
    if err != nil {
		fmt.Printf("   [got errors]\n")
	}else if len(ips) == 0 {
		fmt.Printf("No host record found.")
	}
    for _, ip := range ips {
		fmt.Printf("   %s\n", ip.String())
	}

    fmt.Printf("\nNS record(s):\n")
    nss, err := net.LookupNS(domainName)
	if err != nil {
		fmt.Printf("   [got errors]\n")
	} else if len(nss) == 0 {
		fmt.Printf("No NS records found.")
	}
	for _, ns := range nss {
		fmt.Printf("   %s\n", ns.Host)
	}


    fmt.Printf("\nMX record(s):\n")
    mxs, err := net.LookupMX(domainName)
	if err != nil {
		fmt.Printf("   [got errors]\n")
	}else if len(mxs) == 0 {
		fmt.Printf("No MX records found.")
	}
    for _, mx := range mxs {
		fmt.Printf("   %s %v\n", mx.Host, mx.Pref)
	}
			

    fmt.Printf("\nTXT record(s):\n")
    txts, err := net.LookupTXT(domainName)
	if err != nil {
		fmt.Printf("   [got errors]\n")
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
