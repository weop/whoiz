package main

import (
  "fmt"
  "net"
  "log"
  "os"
  "bytes"
  "os/exec"
  "github.com/urfave/cli"
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

    cmd := exec.Command("bash","-c","whois "+domainName+"| head -n10")
    //todo is there a golib for whois?
    cmdOutput := &bytes.Buffer{}
    cmd.Stdout = cmdOutput
    err := cmd.Run()
    if err != nil {
     os.Stderr.WriteString(err.Error())
    }
    fmt.Printf("\nDomain Reg:\n")
    fmt.Print(string(cmdOutput.Bytes()))


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
