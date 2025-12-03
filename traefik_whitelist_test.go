package whitelist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
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
		{name: "whitespace only", raw: "   ", want: defaultPollInterval},
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

func TestCreateConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := CreateConfig()

	if cfg.PollInterval != "5m" {
		t.Fatalf("unexpected default PollInterval: %q", cfg.PollInterval)
	}
	if cfg.ErrorHTML == "" {
		t.Fatalf("ErrorHTML should not be empty")
	}
	if !cfg.AllowCloudflare || !cfg.AllowFastly || !cfg.AllowAWS {
		t.Fatalf("all CDNs should be allowed by default")
	}
	if cfg.CloudflareIPv4Endpoint == "" ||
		cfg.CloudflareIPv6Endpoint == "" ||
		cfg.FastlyEndpoint == "" ||
		cfg.AWSIPRangesEndpoint == "" {
		t.Fatalf("default endpoints must be set")
	}
}

func TestNewUsesDefaultsAndTrimsHTML(t *testing.T) {
	cfg := &Config{
		PollInterval:           "5m",
		ErrorHTML:              "   ",
		CloudflareIPv4Endpoint: "",
		CloudflareIPv6Endpoint: "",
		FastlyEndpoint:         "",
		AWSIPRangesEndpoint:    "",
	}

	p, err := New(context.Background(), cfg, "test")
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	if p.errorHTML != errorHTMLDefault {
		t.Fatalf("expected default HTML, got %q", p.errorHTML)
	}

	if cfg.CloudflareIPv4Endpoint != defaultCloudflareIPv4Endpoint ||
		cfg.CloudflareIPv6Endpoint != defaultCloudflareIPv6Endpoint ||
		cfg.FastlyEndpoint != defaultFastlyEndpoint ||
		cfg.AWSIPRangesEndpoint != defaultAWSIPRangesEndpoint {
		t.Fatalf("endpoints should be defaulted when empty: %#v", cfg)
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

	overrideFetchers(t, p,
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

	overrideFetchers(t, p,
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

func TestCollectSourcesFailsWhenEmptyNoErrors(t *testing.T) {
	cfg := &Config{AllowCloudflare: false, AllowFastly: false, AllowAWS: false}
	p := newTestProvider(t, cfg)

	_, err := p.collectSources(context.Background())
	if err == nil {
		t.Fatal("collectSources expected error when no sources configured")
	}
	if !strings.Contains(err.Error(), "no CIDR ranges available") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCollectSourcesFailsWhenAllErrors(t *testing.T) {
	cfg := &Config{
		AllowCloudflare: true,
		AllowFastly:     true,
		AllowAWS:        true,
	}
	p := newTestProvider(t, cfg)

	overrideFetchers(t, p,
		stubPlaintextFetcher(nil, map[string]error{
			defaultCloudflareIPv4Endpoint: errors.New("cf v4 err"),
			defaultCloudflareIPv6Endpoint: errors.New("cf v6 err"),
		}),
		stubDualFetcher(nil, nil, errors.New("fastly err")),
		stubDualFetcher(nil, nil, errors.New("aws err")),
	)

	_, err := p.collectSources(context.Background())
	if err == nil {
		t.Fatal("expected error when all sources fail")
	}
	// exact message is not important, but it should aggregate errors
	if !strings.Contains(err.Error(), "cf v4 err") {
		t.Fatalf("expected joined error to mention Cloudflare error, got %v", err)
	}
}

func TestSetCIDRsDetectsChangesAndCopies(t *testing.T) {
	p := newTestProvider(t, CreateConfig())

	if changed := p.setCIDRs([]string{"1.1.1.0/24"}); !changed {
		t.Fatal("expected first setCIDRs call to report changed=true")
	}

	if changed := p.setCIDRs([]string{"1.1.1.0/24"}); changed {
		t.Fatal("expected unchanged CIDRs to report changed=false")
	}

	got := p.currentCIDRs()
	if !slices.Equal(got, []string{"1.1.1.0/24"}) {
		t.Fatalf("currentCIDRs mismatch: %v", got)
	}

	// mutate returned slice and ensure Provider's internal slice is not affected
	got[0] = "2.2.2.0/24"
	if slices.Equal(p.currentCIDRs(), got) {
		t.Fatalf("currentCIDRs should return a defensive copy")
	}
}

func TestBuildConfigurationIncludesErrorService(t *testing.T) {
	p := newTestProvider(t, CreateConfig())
	p.errorURL = "http://127.0.0.1:8080"
	p.setCIDRs([]string{"1.1.1.0/24"})

	cfg := p.buildConfiguration()

	if cfg.HTTP == nil {
		t.Fatalf("HTTP configuration should not be nil")
	}

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

	whitelist := cfg.HTTP.Middlewares[whitelistMiddlewareName]
	if whitelist == nil || whitelist.IPWhiteList == nil {
		t.Fatalf("whitelist middleware missing: %#v", whitelist)
	}
	if !slices.Equal(whitelist.IPWhiteList.SourceRange, []string{"1.1.1.0/24"}) {
		t.Fatalf("unexpected whitelist ranges: %v", whitelist.IPWhiteList.SourceRange)
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

func TestRefreshAndPublishPublishesOnlyOnChange(t *testing.T) {
	cfg := &Config{
		AllowCloudflare: false,
		AllowFastly:     false,
		AllowAWS:        false,
		AdditionalCIDRs: []string{"1.1.1.0/24"},
	}
	p := newTestProvider(t, cfg)

	ch := make(chan json.Marshaler, 2)

	p.refreshAndPublish(context.Background(), ch)
	if len(ch) != 1 {
		t.Fatalf("expected one configuration to be published, got %d", len(ch))
	}
	first := <-ch
	if first == nil {
		t.Fatalf("published configuration should not be nil")
	}

	// Second call with identical CIDRs should not publish again.
	p.refreshAndPublish(context.Background(), ch)
	if len(ch) != 0 {
		t.Fatalf("expected no new configuration on unchanged CIDRs, got %d", len(ch))
	}
}

func TestInitAndErrorServer(t *testing.T) {
	p := newTestProvider(t, CreateConfig())

	if err := p.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if p.errorURL == "" {
		t.Fatal("errorURL should be set after Init")
	}

	resp, err := http.Get(p.errorURL)
	if err != nil {
		t.Fatalf("GET to error server failed: %v", err)
	}

	// avoid shadowing outer err and still log potential close failures
	defer func(body io.ReadCloser) {
		if cerr := body.Close(); cerr != nil {
			t.Logf("closing body failed: %v", cerr)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body failed: %v", err)
	}
	if !bytes.Contains(bodyBytes, []byte("Access Denied")) {
		t.Fatalf("unexpected error page body: %s", string(bodyBytes))
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestBoolPtr(t *testing.T) {
	v := boolPtr(true)
	if v == nil || !*v {
		t.Fatalf("boolPtr(true) = %v, want pointer to true", v)
	}

	v = boolPtr(false)
	if v == nil || *v {
		t.Fatalf("boolPtr(false) = %v, want pointer to false", v)
	}
}

func TestInsertCIDREdgeCases(t *testing.T) {
	// empty string should be a no-op
	if err := insertCIDR("", nil, nil); err != nil {
		t.Fatalf("empty CIDR should not error, got %v", err)
	}

	// invalid CIDR must return error
	if err := insertCIDR("not-a-cidr", nil, nil); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}

	// valid IPv4 with nil v4 tree should be ignored without error
	if err := insertCIDR("1.1.1.0/24", nil, nil); err != nil {
		t.Fatalf("expected no error when v4 tree is nil, got %v", err)
	}

	// valid IPv6 with nil v6 tree should be ignored without error
	if err := insertCIDR("2001:db8::/32", nil, nil); err != nil {
		t.Fatalf("expected no error when v6 tree is nil, got %v", err)
	}
}

// newTestProvider creates a Provider with the given configuration and
// ensures the instance is wiring fetchers that can be overridden in tests.
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

// overrideFetchers swaps the fetcher functions on the Provider instance for tests.
func overrideFetchers(
	t *testing.T,
	p *Provider,
	plaintext func(context.Context, *http.Client, string) ([]string, error),
	fastly func(context.Context, *http.Client, string) ([]string, []string, error),
	aws func(context.Context, *http.Client, string) ([]string, []string, error),
) {
	t.Helper()

	if plaintext == nil && fastly == nil && aws == nil {
		return
	}

	origPlaintext := p.fetchPlaintextCIDRs
	origFastly := p.fetchFastlyRanges
	origAWS := p.fetchAWSRanges

	if plaintext != nil {
		p.fetchPlaintextCIDRs = plaintext
	}
	if fastly != nil {
		p.fetchFastlyRanges = fastly
	}
	if aws != nil {
		p.fetchAWSRanges = aws
	}

	t.Cleanup(func() {
		p.fetchPlaintextCIDRs = origPlaintext
		p.fetchFastlyRanges = origFastly
		p.fetchAWSRanges = origAWS
	})
}

func stubPlaintextFetcher(values map[string][]string, errs map[string]error) func(context.Context, *http.Client, string) ([]string, error) {
	if values == nil {
		values = map[string][]string{}
	}
	if errs == nil {
		errs = map[string]error{}
	}

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
