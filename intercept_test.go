package intercept

import (
	"context"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func NewTestControllerWithZones(input string, zones []string) *caddy.Controller {
	ctr := caddy.NewTestController("dns", input)
	ctr.ServerBlockKeys = append(ctr.ServerBlockKeys, zones...)
	return ctr
}

type testResponseWriter struct {
	test.ResponseWriter
	Rcode int
}

func (t *testResponseWriter) setRemoteIP(ip string) {
	t.RemoteIP = ip
}

// WriteMsg implement dns.ResponseWriter interface.
func (t *testResponseWriter) WriteMsg(m *dns.Msg) error {
	t.Rcode = m.Rcode
	return nil
}

func TestInterceptServeDNS(t *testing.T) {
	type args struct {
		domain   string
		sourceIP string
		qtype    uint16
		ctype    uint16
	}
	tests := []struct {
		name     string
		config   string
		zones    []string
		sourceIP string
		tc       test.Case
		wantErr  bool
	}{
		{
			"Incercept1",
			`intercept example.org {
				record 3600 IN A 127.0.0.2 net 192.168.0.0/16
			}`,
			[]string{},
			"192.168.0.2",
			test.Case{
				Qname: "www.example.org.",
				Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("www.example.org. 3600	IN	A 127.0.0.2"),
				},
			},
			false,
		},
		{
			"Incercept2",
			`intercept example.org {
				record 3600 IN AAAA ::2 net 2001:db8:abcd:0012::0/64
			}`,
			[]string{},
			"2001:db8:abcd:0012::1230",
			test.Case{
				Qname: "www.example.org.",
				Qtype: dns.TypeAAAA,
				Answer: []dns.RR{
					test.AAAA("www.example.org. 3600	IN	AAAA ::2"),
				},
			},
			false,
		},
		{
			"Incercept3",
			`intercept 1.168.192.in-addr.arpa {
				record 600 IN PTR www.example.org. net 192.168.0.0/16
			}`,
			[]string{},
			"192.168.0.2",
			test.Case{
				Qname: "1.1.168.192.in-addr.arpa.",
				Qtype: dns.TypePTR,
				Answer: []dns.RR{
					test.PTR("1.1.168.192.in-addr.arpa. 600	IN	PTR www.example.org."),
				},
			},
			false,
		},
		{
			"Incercept4",
			`intercept example.org {
				record 600 IN TXT "v=spf1 ip4:192.168.0.0/16 -all" net 192.168.0.0/16
			}`,
			[]string{},
			"192.168.0.2",
			test.Case{
				Qname: "example.org.",
				Qtype: dns.TypeTXT,
				Answer: []dns.RR{
					test.TXT("example.org. 600	IN	TXT \"v=spf1 ip4:192.168.0.0/16 -all\""),
				},
			},
			false,
		},
		{
			"Incercept5",
			`intercept example.org {
				record 600 IN NS ns1.example.org. net 192.168.0.0/16
			}`,
			[]string{},
			"192.168.0.2",
			test.Case{
				Qname:  "example.org.",
				Qtype:  dns.TypeNS,
				Answer: []dns.RR{},
			},
			false,
		},
		{
			"Incercept6",
			`intercept example.org {
				record 600 IN A 127.0.0.2 net 192.168.0.0/16
			}`,
			[]string{},
			"192.168.1.2",
			test.Case{
				Qname:  "example.com.",
				Qtype:  dns.TypeA,
				Answer: []dns.RR{},
			},
			false,
		},
		{
			"Incercept7",
			`intercept example.org {
				record 600 IN A 127.0.0.2 net 192.168.0.0/16
			}`,
			[]string{},
			"192.168.0.2",
			test.Case{
				Qname:  "www.example.org.",
				Qtype:  dns.TypeAAAA,
				Answer: []dns.RR{},
			},
			false,
		},
		{
			"Incercept8",
			`intercept example.org {
				record 600 IN A 127.0.0.2 net 192.168.0.0/16
			}`,
			[]string{},
			"10.0.0.1",
			test.Case{
				Qname:  "example.org.",
				Qtype:  dns.TypeA,
				Answer: []dns.RR{},
			},
			false,
		},
		{
			"Incercept9",
			`intercept example.org {
				record 3600 IN A 127.0.0.2 127.0.0.3 net 192.168.0.0/16
			}`,
			[]string{},
			"192.168.0.2",
			test.Case{
				Qname: "www.example.org.",
				Qtype: dns.TypeA,
				Answer: []dns.RR{
					test.A("www.example.org. 3600	IN	A 127.0.0.2"),
					test.A("www.example.org. 3600	IN	A 127.0.0.3"),
				},
			},
			false,
		},
	}
	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctr := NewTestControllerWithZones(tt.config, tt.zones)
			i, err := parse(ctr)
			i.Next = test.NextHandler(dns.RcodeSuccess, nil)
			if err != nil {
				t.Errorf("Error: Cannot intercept config: %v", err)
				return
			}
			w := &testResponseWriter{}
			w.setRemoteIP(tt.sourceIP)
			rec := dnstest.NewRecorder(w)
			m := tt.tc.Msg()
			_, err = i.ServeDNS(ctx, rec, m)
			if (err != nil) != tt.wantErr {
				t.Errorf("Error: intercept.ServeDNS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if resp := rec.Msg; rec.Msg != nil {
				if err := test.SortAndCheck(resp, tt.tc); err != nil {
					t.Error(err)
				}
			}
		})
	}
}
