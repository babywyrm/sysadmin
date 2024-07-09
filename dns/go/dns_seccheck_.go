package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

// DNS query helper function
func queryDNS(domain, recordType string) ([]string, error) {
	var results []string
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.StringToType[recordType])
	r, _, err := c.Exchange(&m, "8.8.8.8:53")
	if err != nil {
		return results, err
	}
	if r.Rcode != dns.RcodeSuccess {
		return results, fmt.Errorf("DNS query failed with Rcode: %d", r.Rcode)
	}
	for _, ans := range r.Answer {
		switch recordType {
		case "TXT":
			if txt, ok := ans.(*dns.TXT); ok {
				results = append(results, txt.Txt...)
			}
		case "CNAME", "A":
			if a, ok := ans.(*dns.CNAME); ok {
				results = append(results, a.Target)
			}
			if a, ok := ans.(*dns.A); ok {
				results = append(results, a.A.String())
			}
		}
	}
	return results, nil
}

// Check DMARC, SPF, and DKIM records
func checkDMARC(domain string) {
	dmarcDomain := "_dmarc." + domain
	spfDomain := domain
	dkimDomain := "default._domainkey." + domain

	dmarcRecords, err := queryDNS(dmarcDomain, "TXT")
	if err != nil {
		log.Printf("Error querying DMARC records for %s: %v", dmarcDomain, err)
		return
	}
	if len(dmarcRecords) == 0 {
		log.Printf("No DMARC records found for %s", dmarcDomain)
	} else {
		for _, record := range dmarcRecords {
			if strings.Contains(record, "v=DMARC1") {
				log.Printf("DMARC record for %s: %s", dmarcDomain, record)
				if strings.Contains(record, "p=reject") || strings.Contains(record, "p=quarantine") {
					log.Println("DMARC policy is effective")
				} else {
					log.Println("DMARC policy is not effective")
				}
			}
		}
	}

	spfRecords, err := queryDNS(spfDomain, "TXT")
	if err != nil {
		log.Printf("Error querying SPF records for %s: %v", spfDomain, err)
		return
	}
	if len(spfRecords) == 0 {
		log.Printf("No SPF records found for %s", spfDomain)
	} else {
		for _, record := range spfRecords {
			if strings.Contains(record, "v=spf1") {
				log.Printf("SPF record for %s: %s", spfDomain, record)
			}
		}
	}

	dkimRecords, err := queryDNS(dkimDomain, "TXT")
	if err != nil {
		log.Printf("Error querying DKIM records for %s: %v", dkimDomain, err)
		return
	}
	if len(dkimRecords) == 0 {
		log.Printf("No DKIM records found for %s", dkimDomain)
	} else {
		for _, record := range dkimRecords {
			log.Printf("DKIM record for %s: %s", dkimDomain, record)
		}
	}
}

func main() {
	domain := "example.com" // replace with the target domain
	checkDMARC(domain)
}




//
//
// queryDNS function: This helper function performs DNS queries for TXT records, which are used for DMARC, SPF, and DKIM.
// checkDMARC function: This function checks for DMARC, SPF, and DKIM records:
// Queries _dmarc.domain for DMARC records and checks if the policy is set to reject or quarantine.
// Queries domain for SPF records.
// Queries default._domainkey.domain for DKIM records.
//  main function: This is the entry point where you specify the domain to check.
