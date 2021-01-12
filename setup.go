package intercept

import (
	"net"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/infobloxopen/go-trees/iptree"
	"github.com/miekg/dns"
)

const (
	pluginName = "intercept"
)

func init() {
	caddy.RegisterPlugin(pluginName, caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func defaultFilter() *iptree.Tree {
	df := iptree.NewTree()
	_, v4, _ := net.ParseCIDR("0.0.0.0/0")
	_, v6, _ := net.ParseCIDR("::/0")
	df.InplaceInsertNet(v4, struct{}{})
	df.InplaceInsertNet(v6, struct{}{})

	return df
}

func normalize(rawNet string) string {
	if idx := strings.IndexAny(rawNet, "/"); idx >= 0 {
		return rawNet
	}

	if idx := strings.IndexAny(rawNet, ":"); idx >= 0 {
		return rawNet + "/128"
	}
	return rawNet + "/32"
}

func setup(c *caddy.Controller) (err error) {
	var i Intercept

	if i, err = parse(c); err != nil {
		return
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		i.Next = next
		return i
	})

	return
}

func parse(c *caddy.Controller) (i Intercept, err error) {
	var source *net.IPNet
	for c.Next() {
		r := rule{}
		r.zones = c.RemainingArgs()
		if len(r.zones) == 0 {
			r.zones = make([]string, len(c.ServerBlockKeys))
			copy(r.zones, c.ServerBlockKeys)
		}
		for i := range r.zones {
			r.zones[i] = plugin.Host(r.zones[i]).Normalize()
		}

		for c.NextBlock() {
			p := policy{}
			p.filter = iptree.NewTree()

			// CLASS
			ctype, ok := dns.StringToClass[c.Val()]
			if !ok {
				err = c.Errf("invalid query class %s", c.Val())
				return
			}
			p.qclasses = make(map[uint16]struct{})
			p.qclasses[ctype] = struct{}{}

			// RR TYPE
			if !c.NextArg() {
				err = c.ArgErr()
				return
			}
			p.qtypes = make(map[uint16]struct{})
			rrType := c.Val()
			if rrType == "*" {
				p.qtypes[dns.TypeNone] = struct{}{}
			} else {
				qtype, ok := dns.StringToType[c.Val()]
				if !ok {
					err = c.Errf("invalid RR type %s", c.Val())
					return
				}
				p.qtypes[qtype] = struct{}{}
			}

			// ANSWER
			if !c.NextArg() {
				err = c.ArgErr()
				return
			}
			p.answer = c.Val()
			if p.answer == "net" || p.answer == "" {
				err = c.Errf("invalid Answer %s", p.answer)
				return
			}
			_, matchA := p.qtypes[dns.TypeA]
			_, matchAAA := p.qtypes[dns.TypeAAAA]
			if matchA || matchAAA {
				ip := net.ParseIP(p.answer)
				if ip == nil {
					err = c.Errf("Invalid IP notation %q", p.answer)
					return
				}
			}

			hasNetPart := false

			remainingTokens := c.RemainingArgs()
			// net label and nets
			if len(remainingTokens) > 0 {
				token := strings.ToLower(remainingTokens[0])
				if token != "net" {
					err = c.Errf("unexpected token %q; expect 'net'", token)
					return
				}

				remainingTokens = remainingTokens[1:]

				if len(remainingTokens) == 0 {
					err = c.Errf("no token specified in %q section", token)
					return
				}

				hasNetPart = true
				for _, token = range remainingTokens {
					if token == "*" {
						p.filter = defaultFilter()
						break
					}
					token = normalize(token)
					_, source, err = net.ParseCIDR(token)
					if err != nil {
						err = c.Errf("illegal CIDR notation %q", token)
						return
					}
					p.filter.InplaceInsertNet(source, struct{}{})
				}
			}

			if !hasNetPart {
				p.filter = defaultFilter()
			}

			r.policies = append(r.policies, p)
		}
		i.Rules = append(i.Rules, r)
	}

	return
}

// intercept {
// 	CLASS RR-TYPE 127.0.0.1 net 192.168.1.0/24
// }
