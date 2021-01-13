package intercept

import (
	"net"
	"strconv"
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
	var qtype uint16
	var source *net.IPNet
	for c.Next() {
		if c.Val() != pluginName {
			continue
		}

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

			// RECORD LABEL
			ttlLabel := c.Val()
			if ttlLabel != "record" {
				err = c.ArgErr()
				return
			}

			// TTL
			if !c.NextArg() {
				err = c.ArgErr()
				return
			}
			ttlVal := c.Val()
			ttl, e := strconv.Atoi(ttlVal)
			if e != nil {
				err = c.Errf("ttl should be a number of second")
				return
			}
			if ttl <= 0 || ttl > 65535 {
				err = c.Errf("ttl provided is invalid")
				return
			}
			p.ttl = uint32(ttl)

			// CLASS
			if !c.NextArg() {
				err = c.ArgErr()
				return
			}
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

			// ANSWERS
			remainingTokens := c.RemainingArgs()
			numTokens := len(remainingTokens)
			if numTokens == 0 {
				err = c.ArgErr()
				return
			}

			index := 0
			answerFound := false
			for ; index < numTokens; index++ {
				ans := remainingTokens[index]
				if !answerFound && strings.ToLower(ans) == "net" {
					err = c.Errf("invalid Answer %s", ans)
					return
				}
				if answerFound && strings.ToLower(ans) == "net" {
					break
				}
				_, matchA := p.qtypes[dns.TypeA]
				_, matchAAA := p.qtypes[dns.TypeAAAA]
				if matchA || matchAAA {
					ip := net.ParseIP(ans)
					if ip == nil {
						err = c.Errf("Invalid IP notation %q", ans)
						return
					}
				}
				if _, isRR := dns.StringToType[ans]; isRR {
					err = c.Errf("Multiple RR Types not allowed, found %q and %q", qtype, ans)
					return
				}
				p.answers = append(p.answers, ans)
				answerFound = true
			}
			remainingTokens = remainingTokens[index:]

			hasNetPart := false

			// net label and nets
			if len(remainingTokens) > 0 {
				// net label
				token := strings.ToLower(remainingTokens[0])
				remainingTokens = remainingTokens[1:]

				// networks
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
