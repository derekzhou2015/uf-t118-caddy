package httpcaddyfile

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// This file is the regression suite for explicit ports on the "bind"
// directive and the "default_bind" global option. It covers every input form
// where the port used to be silently dropped or glued into an illegal listen
// address: bracketed and bare IPv6 literals, empty-host and wildcard
// addresses, placeholder hosts, each with a single port and a port range,
// plus the unix/fd/pure-placeholder/port-less-bare-IPv6 special cases that
// must remain unchanged.

// bind118SiteCaddyfile builds a Caddyfile for an HTTPS site with the given
// raw bind arguments. The bind directive is on line 5.
func bind118SiteCaddyfile(bindArgs string) string {
	return fmt.Sprintf(`{
	auto_https off
}
https://example.com {
	bind %s
	respond ok
}
`, bindArgs)
}

func bind118Adapt(t *testing.T, caddyfileText string) (map[string]any, error) {
	t.Helper()
	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	out, _, err := adapter.Adapt([]byte(caddyfileText), nil)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshalling adapted config: %v\n%s", err, out)
	}
	return cfg, nil
}

func bind118SortedListen(t *testing.T, cfg map[string]any) []string {
	t.Helper()
	var got []string
	apps, _ := cfg["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	for _, rawSrv := range servers {
		srv, _ := rawSrv.(map[string]any)
		listenRaw, _ := srv["listen"].([]any)
		for _, rawLn := range listenRaw {
			if ln, ok := rawLn.(string); ok {
				got = append(got, ln)
			}
		}
	}
	sort.Strings(got)
	return got
}

func bind118FirstBindHost(t *testing.T, cfg map[string]any) string {
	t.Helper()
	apps, _ := cfg["apps"].(map[string]any)
	tlsApp, _ := apps["tls"].(map[string]any)
	automation, _ := tlsApp["automation"].(map[string]any)
	policies, _ := automation["policies"].([]any)
	for _, rawPol := range policies {
		pol, _ := rawPol.(map[string]any)
		issuers, _ := pol["issuers"].([]any)
		for _, rawIss := range issuers {
			iss, _ := rawIss.(map[string]any)
			challenges, _ := iss["challenges"].(map[string]any)
			if bh, ok := challenges["bind_host"].(string); ok {
				return bh
			}
		}
	}
	return ""
}

func bind118AssertListen(t *testing.T, bindArgs string, want []string) {
	t.Helper()
	cfg, err := bind118Adapt(t, bind118SiteCaddyfile(bindArgs))
	if err != nil {
		t.Fatalf("bind %q: unexpected adapt error: %v", bindArgs, err)
	}
	got := bind118SortedListen(t, cfg)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bind %q: listen mismatch\nwant: %#v\ngot:  %#v", bindArgs, want, got)
	}
}

// A legal explicit port/range must reach the listen list verbatim instead of
// being replaced by the site's default port.
func TestBindExplicitPortForms(t *testing.T) {
	for _, tc := range []struct {
		args string
		want []string
	}{
		// IPv4 / host with single port and range
		{"127.0.0.1:8080", []string{"127.0.0.1:8080"}},
		{"127.0.0.1:8080-8090", []string{"127.0.0.1:8080-8090"}},
		{"10.0.0.2:9000-9002", []string{"10.0.0.2:9000-9002"}},

		// bracketed IPv6 with port and range
		{"[::1]:8080", []string{"[::1]:8080"}},
		{"[::1]:8080-8090", []string{"[::1]:8080-8090"}},
		{"[2001:db8::1]:4430", []string{"[2001:db8::1]:4430"}},
		{"[::]:8080", []string{"[::]:8080"}},

		// bare IPv6 literal with an appended port/range is legalized into
		// the bracketed listener rather than glued into the host
		{"::1:8080", []string{"[::1]:8080"}},
		{"::1:8080-8090", []string{"[::1]:8080-8090"}},

		// empty host (all interfaces) with port/range
		{":8080", []string{":8080"}},
		{":8080-8090", []string{":8080-8090"}},

		// wildcard address with port and range
		{"*:8080", []string{"*:8080"}},
		{"*:8080-8090", []string{"*:8080-8090"}},

		// explicit unspecified IPv4/IPv6 wildcard IPs with port and range
		{"0.0.0.0:8080", []string{"0.0.0.0:8080"}},
		{"0.0.0.0:8080-8090", []string{"0.0.0.0:8080-8090"}},
		{"[::]:8080-8090", []string{"[::]:8080-8090"}},

		// placeholder host with literal port/range
		{"{env.MYHOST}:8080", []string{"{env.MYHOST}:8080"}},
		{"{env.MYHOST}:8080-8090", []string{"{env.MYHOST}:8080-8090"}},

		// explicit network prefix; default "tcp" network is omitted by the
		// network-address normalization, tcp4/tcp6 are retained
		{"tcp/127.0.0.1:9000", []string{"127.0.0.1:9000"}},
		{"tcp/127.0.0.1:9000-9002", []string{"127.0.0.1:9000-9002"}},
		{"tcp4/0.0.0.0:9000", []string{"tcp4/0.0.0.0:9000"}},
		{"tcp6/[::]:9000", []string{"tcp6/[::]:9000"}},
		{"tcp6/::1:9000", []string{"tcp6/[::1]:9000"}},
	} {
		bind118AssertListen(t, tc.args, tc.want)
	}
}

// Addresses without an explicit port keep inheriting the site port exactly
// as before, including the protected special forms.
func TestBindPortlessAndSpecialAddressesUnchanged(t *testing.T) {
	for _, tc := range []struct {
		args string
		want []string
	}{
		// ordinary port-less hosts inherit the HTTPS port
		{"127.0.0.1", []string{"127.0.0.1:443"}},
		{"localhost", []string{"localhost:443"}},
		{"0.0.0.0", []string{"0.0.0.0:443"}},
		{"*", []string{"*:443"}},

		// bracketed and bare port-less IPv6 literals are not mangled
		{"[::1]", []string{"[::1]:443"}},
		{"[::]", []string{"[::]:443"}},
		{"::1", []string{"[::1]:443"}},
		{"2001:db8::1", []string{"[2001:db8::1]:443"}},

		// pure placeholder address is untouched apart from the inherited port
		{"{env.MYHOST}", []string{"{env.MYHOST}:443"}},

		// unix sockets, including paths that contain colons
		{"unix//run/sock", []string{"unix//run/sock"}},
		{"unix//run/x:sock", []string{"unix//run/x:sock"}},
		{"unix//run/http:8080.sock", []string{"unix//run/http:8080.sock"}},

		// file descriptor addresses and placeholder descriptor names
		{"fd/3", []string{"fd/3"}},
		{"fd/{systemd.listen.web}", []string{"fd/{systemd.listen.web}"}},
		{"fdgram/{env.CADDY_HTTP3_FD}", []string{"fdgram/{env.CADDY_HTTP3_FD}"}},
	} {
		bind118AssertListen(t, tc.args, tc.want)
	}
}

// Two explicit ports on the same host must remain two listeners.
func TestBindSameHostMultipleExplicitPortsNotMerged(t *testing.T) {
	cfg, err := bind118Adapt(t, bind118SiteCaddyfile("127.0.0.1:8080 127.0.0.1:9090"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := bind118SortedListen(t, cfg)
	want := []string{"127.0.0.1:8080", "127.0.0.1:9090"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("explicit ports merged or missing\nwant: %v\ngot:  %v", want, got)
	}
}

// Repeating the exact same listener stays de-duplicated.
func TestBindDuplicateListenerStillDeduplicated(t *testing.T) {
	bind118AssertListen(t, "127.0.0.1:8080 127.0.0.1:8080", []string{"127.0.0.1:8080"})
}

// Mixing explicit-port and port-less addresses in one directive applies one
// uniform rule: explicit wins, otherwise the site port is inherited.
func TestBindMixedExplicitAndPortlessUniform(t *testing.T) {
	cfg, err := bind118Adapt(t, bind118SiteCaddyfile("127.0.0.1 10.0.0.2:9090"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := bind118SortedListen(t, cfg)
	want := []string{"10.0.0.2:9090", "127.0.0.1:443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mixed bind handling mismatch\nwant: %v\ngot:  %v", want, got)
	}
}

// The site key's host routing match must survive the address expansion.
func TestBindKeepsSiteHostRoutingMatch(t *testing.T) {
	cfg, err := bind118Adapt(t, bind118SiteCaddyfile("127.0.0.1:8080 127.0.0.1:9090"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	apps := cfg["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	foundHostMatch := false
	for _, rawSrv := range servers {
		srv := rawSrv.(map[string]any)
		routes, _ := srv["routes"].([]any)
		for _, rawRoute := range routes {
			route := rawRoute.(map[string]any)
			match, _ := route["match"].([]any)
			for _, rawM := range match {
				m := rawM.(map[string]any)
				hosts, _ := m["host"].([]any)
				for _, h := range hosts {
					if h == "example.com" {
						foundHostMatch = true
					}
				}
			}
		}
	}
	if !foundHostMatch {
		t.Fatalf("site key host match example.com not preserved: %#v", servers)
	}
}

// Invalid explicit ports must fail adaptation with the established port
// violation wording and the config line of the offending address.
func TestBindInvalidPortErrorsWithLine(t *testing.T) {
	for _, tc := range []struct {
		name      string
		caddyfile string
		line      int
		wantSub   string
	}{
		{
			name: "site bind non numeric",
			caddyfile: `https://example.com {
	bind 127.0.0.1:notaport
}
`,
			line:    2,
			wantSub: "invalid port 'notaport'",
		},
		{
			name: "site bind out of range",
			caddyfile: `https://example.com {
	bind 127.0.0.1:70000
}
`,
			line:    2,
			wantSub: "port 70000 is out of range",
		},
		{
			name: "site bind empty host out of range",
			caddyfile: `https://example.com {
	bind :99999
}
`,
			line:    2,
			wantSub: "port 99999 is out of range",
		},
		{
			name: "site bind negative port",
			caddyfile: `https://example.com {
	bind :-1
}
`,
			line:    2,
			wantSub: "port -1 is out of range",
		},
		{
			name: "site bind bracketed ipv6 out of range",
			caddyfile: `https://example.com {
	bind [::1]:70000
}
`,
			line:    2,
			wantSub: "port 70000 is out of range",
		},
		{
			name: "site bind reversed range",
			caddyfile: `https://example.com {
	bind 127.0.0.1:8080-7000
}
`,
			line:    2,
			wantSub: "end port must not be less than start port",
		},
		{
			name: "global default_bind invalid port",
			caddyfile: `{
	default_bind 127.0.0.1:70000
}
example.com {
	respond ok
}
`,
			line:    2,
			wantSub: "port 70000 is out of range",
		},
		{
			name: "mixed valid and invalid fails whole adapt",
			caddyfile: `https://example.com {
	bind 127.0.0.1:8080 10.0.0.2:badport
}
`,
			line:    2,
			wantSub: "invalid port 'badport'",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := bind118Adapt(t, tc.caddyfile)
			if err == nil {
				t.Fatalf("expected adaptation error containing %q, got nil", tc.wantSub)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.wantSub) {
				t.Errorf("error %q does not contain %q", msg, tc.wantSub)
			}
			wantLine := fmt.Sprintf("at Caddyfile:%d", tc.line)
			if !strings.Contains(msg, wantLine) {
				t.Errorf("error %q does not contain line marker %q", msg, wantLine)
			}
		})
	}
}

// The scheme/port convention check must continue to be based solely on the
// site address port, not on an explicit bind port.
func TestBindSchemeConventionUsesSitePortOnly(t *testing.T) {
	// http site (site port 80) bound to an explicit 443 is not a convention
	// violation because the bind port is not the site address port.
	if _, err := bind118Adapt(t, bind118SiteCaddyfileWithScheme("http://example.com", "1.2.3.4:443")); err != nil {
		t.Fatalf("http site + bind :443 should be allowed, got: %v", err)
	}
	// https site (site port 443) bound to an explicit 80 is likewise allowed.
	if _, err := bind118Adapt(t, bind118SiteCaddyfileWithScheme("https://example.com", "1.2.3.4:80")); err != nil {
		t.Fatalf("https site + bind :80 should be allowed, got: %v", err)
	}

	// the site-key convention violations themselves are still rejected
	for _, key := range []string{"http://example.com:443", "https://example.com:80"} {
		cf := fmt.Sprintf(`{
	auto_https off
}
%s {
	respond ok
}
`, key)
		if _, err := bind118Adapt(t, cf); err == nil || !strings.Contains(err.Error(), "scheme and port violate convention") {
			t.Fatalf("key %s: expected convention error, got %v", key, err)
		}
	}
}

func bind118SiteCaddyfileWithScheme(schemeKey, bindArgs string) string {
	return fmt.Sprintf(`{
	auto_https off
}
%s {
	bind %s
	respond ok
}
`, schemeKey, bindArgs)
}

// ACME challenge bind_host must be host-only: no port and no network prefix
// that could contradict the actual listener port. Covers both the site bind
// and the global default_bind fallback.
func TestBindHostHasNoPort(t *testing.T) {
	for _, tc := range []struct {
		name       string
		caddyfile  string
		wantHost   string
		wantListen []string
	}{
		{
			name: "site ipv4 port",
			caddyfile: `example.com {
	bind 127.0.0.1:8080
	tls {
		issuer acme
	}
}
`,
			wantHost:   "127.0.0.1",
			wantListen: []string{"127.0.0.1:8080"},
		},
		{
			name: "site bracketed ipv6 port",
			caddyfile: `example.com {
	bind [::1]:8080
	tls {
		issuer acme
	}
}
`,
			wantHost:   "::1",
			wantListen: []string{"[::1]:8080"},
		},
		{
			name: "site network prefix and port",
			caddyfile: `example.com {
	bind tcp/10.0.0.1:9000
	tls {
		issuer acme
	}
}
`,
			wantHost:   "10.0.0.1",
			wantListen: []string{"10.0.0.1:9000"},
		},
		{
			name: "global default bind port",
			caddyfile: `{
	default_bind 192.168.1.1:7000
}
example.com {
	tls {
		issuer acme
	}
}
`,
			wantHost:   "192.168.1.1",
			wantListen: []string{"192.168.1.1:7000"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := bind118Adapt(t, tc.caddyfile)
			if err != nil {
				t.Fatalf("unexpected adapt error: %v", err)
			}
			if bh := bind118FirstBindHost(t, cfg); bh != tc.wantHost {
				t.Fatalf("bind_host mismatch: want %q, got %q", tc.wantHost, bh)
			}
			gotListen := bind118SortedListen(t, cfg)
			sort.Strings(tc.wantListen)
			if !reflect.DeepEqual(gotListen, tc.wantListen) {
				t.Fatalf("listen mismatch: want %v, got %v", tc.wantListen, gotListen)
			}
		})
	}
}

// The global http_port/https_port options still supply the inherited port for
// bind addresses that do not specify one, while an explicit bind port wins.
func TestBindGlobalPortOptionsAndProtocolsBlock(t *testing.T) {
	cf := `{
	auto_https off
	https_port 8443
}
https://example.com {
	bind 127.0.0.1
	respond ok
}
`
	cfg, err := bind118Adapt(t, cf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := bind118SortedListen(t, cfg); !reflect.DeepEqual(got, []string{"127.0.0.1:8443"}) {
		t.Fatalf("global https_port not inherited: %v", got)
	}

	// explicit bind port overrides the global default
	cf2 := `{
	auto_https off
	https_port 8443
}
https://example.com {
	bind 127.0.0.1:9443
	respond ok
}
`
	cfg2, err := bind118Adapt(t, cf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := bind118SortedListen(t, cfg2); !reflect.DeepEqual(got, []string{"127.0.0.1:9443"}) {
		t.Fatalf("explicit bind port should win over global https_port: %v", got)
	}

	// port-bearing addresses must still parse a trailing protocols block
	cf3 := `https://example.com {
	bind 127.0.0.1:8080 {
		protocols h1 h2
	}
	respond ok
}
`
	cfg3, err := bind118Adapt(t, cf3)
	if err != nil {
		t.Fatalf("bind with port + protocols block failed: %v", err)
	}
	if got := bind118SortedListen(t, cfg3); !reflect.DeepEqual(got, []string{"127.0.0.1:8080"}) {
		t.Fatalf("protocols-block listen mismatch: %v", got)
	}
}

// The global default_bind entry applies the same explicit-port rules as the
// site-level bind directive.
func TestDefaultBindExplicitPorts(t *testing.T) {
	cf := `{
	auto_https off
	default_bind 127.0.0.1:8080 127.0.0.1:9090
}
https://example.com {
	respond ok
}
`
	cfg, err := bind118Adapt(t, cf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := bind118SortedListen(t, cfg); !reflect.DeepEqual(got, []string{"127.0.0.1:8080", "127.0.0.1:9090"}) {
		t.Fatalf("default_bind explicit ports wrong/merged: %v", got)
	}

	// port-less default_bind still inherits the site port
	cf2 := `{
	auto_https off
	default_bind 10.0.0.2
}
https://example.com {
	respond ok
}
`
	cfg2, err := bind118Adapt(t, cf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := bind118SortedListen(t, cfg2); !reflect.DeepEqual(got, []string{"10.0.0.2:443"}) {
		t.Fatalf("port-less default_bind should inherit site port: %v", got)
	}
}

// White-box coverage of the shared splitter/validator across the full form
// inventory.
func TestSplitBindAddressInventory(t *testing.T) {
	for _, tc := range []struct {
		raw             string
		wantNet         string
		wantHost        string
		wantPort        string
		wantErrContains string
	}{
		{raw: "127.0.0.1", wantHost: "127.0.0.1"},
		{raw: "127.0.0.1:8080", wantHost: "127.0.0.1", wantPort: "8080"},
		{raw: "127.0.0.1:8080-8090", wantHost: "127.0.0.1", wantPort: "8080-8090"},
		{raw: "[::1]", wantHost: "::1"},
		{raw: "[::1]:8080", wantHost: "::1", wantPort: "8080"},
		{raw: "[::1]:8080-8090", wantHost: "::1", wantPort: "8080-8090"},
		{raw: "::1", wantHost: "::1"},
		{raw: "2001:db8::1", wantHost: "2001:db8::1"},
		{raw: "::1:8080", wantHost: "::1", wantPort: "8080"},
		{raw: "::1:8080-8090", wantHost: "::1", wantPort: "8080-8090"},
		{raw: ":8080", wantHost: "", wantPort: "8080"},
		{raw: ":8080-8090", wantHost: "", wantPort: "8080-8090"},
		{raw: "*:8080", wantHost: "*", wantPort: "8080"},
		{raw: "{env.H}:8080", wantHost: "{env.H}", wantPort: "8080"},
		{raw: "{env.H}", wantHost: "{env.H}"},
		{raw: "unix//run/x:sock", wantNet: "unix", wantHost: "/run/x:sock"},
		{raw: "fd/{systemd.x}", wantNet: "fd", wantHost: "{systemd.x}"},
		{raw: "tcp6/::1:9000", wantNet: "tcp6", wantHost: "::1", wantPort: "9000"},
		{raw: "127.0.0.1:bad", wantErrContains: "invalid port 'bad'"},
		{raw: "127.0.0.1:70000", wantErrContains: "port 70000 is out of range"},
		{raw: ":-1", wantErrContains: "port -1 is out of range"},
		{raw: "127.0.0.1:80-70", wantErrContains: "end port must not be less than start port"},
		{raw: "127.0.0.1:0-65535", wantErrContains: "port range exceeds"},
	} {
		netw, host, port, err := splitBindAddress(tc.raw)
		if tc.wantErrContains != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Errorf("%q: expected error containing %q, got %v", tc.raw, tc.wantErrContains, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.raw, err)
			continue
		}
		if netw != tc.wantNet || host != tc.wantHost || port != tc.wantPort {
			t.Errorf("%q: got (%q,%q,%q); want (%q,%q,%q)", tc.raw, netw, host, port, tc.wantNet, tc.wantHost, tc.wantPort)
		}
	}
}
