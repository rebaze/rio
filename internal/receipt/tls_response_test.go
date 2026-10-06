package receipt

import "testing"

func TestResponseTLSContradictions(t *testing.T) {
	yes, no := true, false
	for name, change := range map[string]func(*Document){
		"HTTP TLS": func(d *Document) {
			d.Targets["security"] = Target{Type: "dependency-track", URL: "http://receiver.example.org"}
			d.Deliveries[0].Transport = Transport{Scheme: "http", CertificateVerification: "not-applicable"}
			d.Deliveries[0].Responses[0].TLSObserved = &yes
		},
		"HTTPS response without TLS": func(d *Document) { d.Deliveries[0].Responses[0].TLSObserved = &no },
		"response contradicts aggregate": func(d *Document) {
			d.Deliveries[0].Responses[0].TLSObserved = &yes
			d.Deliveries[0].Transport.TLSObserved = &no
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := fixture()
			change(&d)
			if _, e := Marshal(d); e == nil {
				t.Fatal("contradictory TLS accepted")
			}
		})
	}
}
