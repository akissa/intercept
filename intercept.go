package intercept

import (
	"context"
	"net"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/infobloxopen/go-trees/iptree"
	"github.com/miekg/dns"
)

type rule struct {
	zones    []string
	policies []policy
}

type policy struct {
	answers  []string
	ttl      uint32
	qclasses map[uint16]struct{}
	qtypes   map[uint16]struct{}
	filter   *iptree.Tree
}

// Intercept implements the intercept plugin
type Intercept struct {
	Next  plugin.Handler
	Rules []rule
}

// Name implements the Handler interface.
func (i Intercept) Name() string {
	return pluginName
}

// ServeDNS implements the plugin.Handler interface.
func (i Intercept) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	src := net.ParseIP(state.IP())
	qname := state.Name()
	qtype := state.QType()
	qclass := state.QClass()

	for _, rule := range i.Rules {
		zone := plugin.Zones(rule.zones).Matches(state.Name())
		if zone == "" {
			continue
		}

		answers := []dns.RR{}

		for _, policy := range rule.policies {
			_, matchClass := policy.qclasses[qclass]
			if !matchClass {
				continue
			}
			_, matchAllTypes := policy.qtypes[dns.TypeNone]
			_, matchType := policy.qtypes[qtype]
			if !matchAllTypes && !matchType {
				continue
			}

			_, inNet := policy.filter.GetByIP(src)
			if !inNet {
				continue
			}

			//matched
			switch qtype {
			case dns.TypeA:
				for _, ans := range policy.answers {
					answer := new(dns.A)
					answer.Hdr = dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    policy.ttl,
					}
					answer.A = net.ParseIP(ans)
					answers = append(answers, answer)
				}
			case dns.TypeAAAA:
				for _, ans := range policy.answers {
					answer := new(dns.AAAA)
					answer.Hdr = dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    policy.ttl,
					}
					answer.AAAA = net.ParseIP(ans)
					answers = append(answers, answer)
				}
			case dns.TypePTR:
				for _, ans := range policy.answers {
					answer := new(dns.PTR)
					answer.Hdr = dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    policy.ttl,
					}
					answer.Ptr = dns.Fqdn(ans)
					answers = append(answers, answer)
				}
			case dns.TypeTXT:
				for _, ans := range policy.answers {
					answer := new(dns.TXT)
					answer.Hdr = dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    policy.ttl,
					}
					answer.Txt = append(answer.Txt, ans)
					answers = append(answers, answer)
				}
			default:
				continue
			}

			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = answers
			w.WriteMsg(m)

			return dns.RcodeSuccess, nil
		}
	}

	return plugin.NextOrFailure(state.Name(), i.Next, ctx, w, r)
}
