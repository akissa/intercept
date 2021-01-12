package intercept

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
	}{
		// IPv4 tests.
		{
			"Intercept 1",
			`intercept {
				IN A 127.0.0.2 net 192.168.0.0/16
			}`,
			false,
		},
		{
			"Intercept 2",
			`intercept {
				IN * 127.0.0.2 net 192.168.0.0/16
			}`,
			false,
		},
		{
			"Intercept 3",
			`intercept {
				IN A 127.0.0.2 net *
			}`,
			false,
		},
		{
			"Intercept 4",
			`intercept {
				IN TXT "The sender is not allowed to query this server" net 192.168.1.0/24
			}`,
			false,
		},
		{
			"Intercept wildcards",
			`intercept {
				IN * 127.0.0.2 net 192.168.0.0/16
				IN * 127.0.0.2 net *
			}`,
			false,
		},
		{
			"fine-grained 1",
			`intercept a.example.org {
				IN * 127.0.0.2 net 192.168.1.0/24
			}`,
			false,
		},
		{
			"fine-grained 2",
			`intercept a.example.org {
				IN * 127.0.0.2 net 192.168.1.0/24
			}
			intercept b.example.org {
				IN * 127.0.0.2 net 192.168.2.0/24
			}`,
			false,
		},
		{
			"Multiple Networks 1",
			`intercept example.org {
				IN * 127.0.0.2 net 192.168.1.0/24 192.168.3.0/24
			}`,
			false,
		},
		{
			"Multiple Qtypes 1",
			`intercept example.org {
				IN TXT ANY 127.0.0.2 net 192.168.3.0/24
			}`,
			true,
		},
		{
			"Missing argument 1",
			`intercept {
				A 127.0.0.2 net 192.168.0.0/16
			}`,
			true,
		},
		{
			"Missing argument 2",
			`intercept {
				IN 127.0.0.2 net 192.168.0.0/16
			}`,
			true,
		},
		{
			"Missing argument 3",
			`intercept {
				IN
			}`,
			true,
		},
		{
			"Missing argument 4",
			`intercept {
				IN A
			}`,
			true,
		},
		{
			"Missing argument 5",
			`intercept {
				IN A net
			}`,
			true,
		},
		{
			"Missing argument 6",
			`intercept {
				IN A 127.0.0.2 net
			}`,
			true,
		},
		{
			"Illegal argument 1",
			`intercept {
				IN ABC 127.0.0.2 net 192.168.0.0/16
			}`,
			true,
		},
		{
			"Illegal argument 2",
			`intercept {
				blck A 127.0.0.2 net 192.168.0.0/16
			}`,
			true,
		},
		{
			"Illegal argument 3",
			`intercept {
				IN A 127.0.0.2 net 192.168.0/16
			}`,
			true,
		},
		{
			"Illegal argument 4",
			`intercept {
				IN A 127.0.0.2 net 192.168.0.0/33
			}`,
			true,
		},
		{
			"Illegal argument 5",
			`intercept {
				IN A 127.0.0.260 net 192.168.0.0/33
			}`,
			true,
		},
		// IPv6 tests.
		{
			"Intercept 1 IPv6",
			`intercept {
				IN A ::2 net 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			}`,
			false,
		},
		{
			"Intercept 2 IPv6",
			`intercept {
				IN * ::2 net 2001:db8:85a3::8a2e:370:7334
			}`,
			false,
		},
		{
			"Intercept 3 IPv6",
			`intercept {
				IN A ::2
			}`,
			false,
		},
		{
			"fine-grained 1 IPv6",
			`intercept a.example.org {
				IN A ::2 net 2001:db8:abcd:0012::0/64
			}`,
			false,
		},
		{
			"fine-grained 2 IPv6",
			`intercept a.example.org {
				IN A ::2 net 2001:db8:abcd:0012::0/64
			}
			intercept b.example.org {
				IN A ::2 net 2001:db8:abcd:0013::0/64
			}`,
			false,
		},
		{
			"Multiple Networks 1 IPv6",
			`intercept example.org {
				IN A ::2 net 2001:db8:abcd:0012::0/64 2001:db8:85a3::8a2e:370:7334/64
			}`,
			false,
		},
		{
			"Illegal argument 1 IPv6",
			`intercept {
				IN A ::2 net 2001::85a3::8a2e:370:7334
			}`,
			true,
		},
		{
			"Illegal argument 2 IPv6",
			`intercept {
				IN A ::2 net 2001:db8:85a3:::8a2e:370:7334
			}`,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctr := caddy.NewTestController("dns", tt.config)
			if err := setup(ctr); (err != nil) != tt.wantErr {
				t.Errorf("Error: setup() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	type args struct {
		rawNet string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"Network range 1",
			args{"10.218.10.8/24"},
			"10.218.10.8/24",
		},
		{
			"IP address 1",
			args{"10.218.10.8"},
			"10.218.10.8/32",
		},
		{
			"IPv6 address 1",
			args{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			"2001:0db8:85a3:0000:0000:8a2e:0370:7334/128",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalize(tt.args.rawNet); got != tt.want {
				t.Errorf("Error: normalize() = %v, want %v", got, tt.want)
			}
		})
	}
}
