package whitelist

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"testing"
	"time"
)

func TestParsePollInterval(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "default when empty", raw: "", want: defaultPollInterval},
		{name: "default on parse error", raw: "not-a-duration", want: defaultPollInterval},
		{name: "clamped to minimum", raw: "10ms", want: minimumPollInterval},
		{name: "valid duration", raw: "1m", want: time.Minute},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parsePollInterval(tc.raw)
			if got != tc.want {
				t.Fatalf("parsePollInterval(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestCollectSourcesAggregatesRanges(t *testing.T) {
	cfg := &Config{
		AllowCloudflare:        true,
		AllowFastly:            true,
		AllowAWS:               true,
		AdditionalCIDRs:        []string{"10.0.0.0/8", "2001:db8:ffff::/48"},
		CloudflareIPv4Endpoint: "cf4",
		CloudflareIPv6Endpoint: "cf6",
		FastlyEndpoint:         "fastly",
		AWSIPRangesEndpoint:    "aws",
	}

	p := newTestProvider(t, cfg)

	overrideFetchers(t,
		stubPlaintextFetcher(map[string][]string{
			"cf4": {"1.1.1.0/24"},
			"cf6": {"2001:4860::/32"},
		}, nil),
		stubDualFetcher([]string{"2.2.2.0/24"}, []string{"2001:db8:1::/48"}, nil),
		stubDualFetcher([]string{"3.3.3.0/24"}, []string{"2001:db8:2::/48"}, nil),
	)

	cidrs, err := p.collectSources(context.Background())
	if err != nil {
		t.Fatalf("collectSources returned error: %v", err)
	}

	expected := []string{
		"1.1.1.0/24",
		"2.2.2.0/24",
		"3.3.3.0/24",
		"10.0.0.0/8",
		"2001:4860::/32",
		"2001:db8:ffff::/48",
		"2001:db8:1::/48",
		"2001:db8:2::/48",
	}
	sort.Strings(expected)

	if !slices.Equal(cidrs, expected) {
		t.Fatalf("collectSources unexpected result: got %v want %v", cidrs, expected)
	}
}

func TestCollectSourcesHandlesPartialErrors(t *testing.T) {
	cfg := &Config{
		AllowCloudflare:        true,
		AllowFastly:            false,
		AllowAWS:               false,
		CloudflareIPv4Endpoint: "cf4",
		CloudflareIPv6Endpoint: "cf6",
	}
	p := newTestProvider(t, cfg)

	overrideFetchers(t,
		stubPlaintextFetcher(
			map[string][]string{"cf4": {"1.1.1.0/24"}},
			map[string]error{"cf6": errors.New("boom")},
		),
		nil,
		nil,
	)

	cidrs, err := p.collectSources(context.Background())
	if err != nil {
		t.Fatalf("collectSources returned error: %v", err)
	}

	if want := []string{"1.1.1.0/24"}; !slices.Equal(cidrs, want) {
		t.Fatalf("unexpected CIDRs: got %v want %v", cidrs, want)
	}
}

func TestCollectSourcesFailsWhenEmpty(t *testing.T) {
	cfg := &Config{AllowCloudflare: false, AllowFastly: false, AllowAWS: false}
	p := newTestProvider(t, cfg)

	_, err := p.collectSources(context.Background())
	if err == nil {
		t.Fatal("collectSources expected error when no sources configured")
	}
}

func TestBuildConfigurationIncludesErrorService(t *testing.T) {
	p := newTestProvider(t, CreateConfig())
	p.errorURL = "http://127.0.0.1:8080"
	p.setCIDRs([]string{"1.1.1.0/24"})

	cfg := p.buildConfiguration()

	svc := cfg.HTTP.Services[blockedServiceName]
	if svc == nil || svc.LoadBalancer == nil || len(svc.LoadBalancer.Servers) != 1 {
		t.Fatalf("blocked service not configured: %#v", svc)
	}

	if svc.LoadBalancer.Servers[0].URL != p.errorURL {
		t.Fatalf("expected error URL %q got %q", p.errorURL, svc.LoadBalancer.Servers[0].URL)
	}

	chain := cfg.HTTP.Middlewares[chainMiddlewareName]
	if chain == nil || chain.Chain == nil {
		t.Fatalf("chain middleware missing: %#v", chain)
	}

	wantChain := []string{whitelistMiddlewareName, errorMiddlewareName}
	if !slices.Equal(chain.Chain.Middlewares, wantChain) {
		t.Fatalf("chain order mismatch: got %v want %v", chain.Chain.Middlewares, wantChain)
	}
}

func TestBuildConfigurationOmitsErrorServiceWithoutURL(t *testing.T) {
	p := newTestProvider(t, CreateConfig())
	p.errorURL = ""
	p.setCIDRs([]string{"1.1.1.0/24"})

	cfg := p.buildConfiguration()

	if _, ok := cfg.HTTP.Services[blockedServiceName]; ok {
		t.Fatalf("blocked service should be omitted when no error URL")
	}
}

func newTestProvider(t *testing.T, cfg *Config) *Provider {
	t.Helper()
	if cfg == nil {
		cfg = CreateConfig()
	}

	p, err := New(context.Background(), cfg, "test")
	if err != nil {
		t.Fatalf("New provider failed: %v", err)
	}

	return p
}

func overrideFetchers(t *testing.T,
	plaintext func(context.Context, *http.Client, string) ([]string, error),
	fastly func(context.Context, *http.Client, string) ([]string, []string, error),
	aws func(context.Context, *http.Client, string) ([]string, []string, error),
) {
	t.Helper()

	if plaintext == nil && fastly == nil && aws == nil {
		return
	}

	origPlaintext := fetchPlaintextCIDRs
	origFastly := fetchFastlyRanges
	origAWS := fetchAWSRanges

	if plaintext != nil {
		fetchPlaintextCIDRs = plaintext
	}
	if fastly != nil {
		fetchFastlyRanges = fastly
	}
	if aws != nil {
		fetchAWSRanges = aws
	}

	t.Cleanup(func() {
		fetchPlaintextCIDRs = origPlaintext
		fetchFastlyRanges = origFastly
		fetchAWSRanges = origAWS
	})
}

func stubPlaintextFetcher(values map[string][]string, errs map[string]error) func(context.Context, *http.Client, string) ([]string, error) {
	return func(_ context.Context, _ *http.Client, endpoint string) ([]string, error) {
		if err, ok := errs[endpoint]; ok {
			return nil, err
		}
		if ranges, ok := values[endpoint]; ok {
			out := slices.Clone(ranges)
			return out, nil
		}
		return nil, fmt.Errorf("unexpected endpoint %q", endpoint)
	}
}

func stubDualFetcher(v4, v6 []string, err error) func(context.Context, *http.Client, string) ([]string, []string, error) {
	return func(context.Context, *http.Client, string) ([]string, []string, error) {
		if err != nil {
			return nil, nil, err
		}
		return slices.Clone(v4), slices.Clone(v6), nil
	}
}
