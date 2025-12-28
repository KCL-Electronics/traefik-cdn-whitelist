// Package whitelist provides a Traefik dynamic configuration provider that
// restricts access to services behind specific CDN IP ranges.
package whitelist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KCL-Electronics/traefik-cdn-whitelist/internal/cidrtree" //nolint:depguard // internal usage is intentional for plugin wiring
	"github.com/KCL-Electronics/traefik-cdn-whitelist/internal/fetchers" //nolint:depguard // internal usage is intentional for plugin wiring
	"github.com/traefik/genconf/dynamic"                                 //nolint:depguard // Traefik plugin API is allowed here
)

const (
	defaultPollInterval = 5 * time.Minute
	minimumPollInterval = time.Second
	fetchTimeout        = 30 * time.Second
	shutdownTimeout     = 2 * time.Second
	serverTimeout       = 5 * time.Second

	errorHTMLDefault = `<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1><p>Please access this service through the authorized CDN. This attempt has been logged.</p></body></html>`

	blockedServiceName      = "cdn-blocked-service"
	whitelistMiddlewareName = "cdn-whitelist"
	errorMiddlewareName     = "cdn-whitelist-errors"
	chainMiddlewareName     = "cdn-whitelist-chain"

	ipv4Bits = 32
	ipv6Bits = 128
)

const (
	defaultCloudflareIPv4Endpoint = "https://www.cloudflare.com/ips-v4/"
	defaultCloudflareIPv6Endpoint = "https://www.cloudflare.com/ips-v6/"
	defaultFastlyEndpoint         = "https://api.fastly.com/public-ip-list"
	defaultAWSIPRangesEndpoint    = "https://ip-ranges.amazonaws.com/ip-ranges.json"
)

// Config controls the CDN whitelist provider behavior.
type Config struct {
	PollInterval           string   `json:"pollInterval,omitempty"`
	ErrorHTML              string   `json:"errorHtml,omitempty"`
	AllowCloudflare        bool     `json:"allowCloudflare,omitempty"`
	AllowFastly            bool     `json:"allowFastly,omitempty"`
	AllowAWS               bool     `json:"allowAws,omitempty"`
	AdditionalCIDRs        []string `json:"additionalCidRs,omitempty"`
	CloudflareIPv4Endpoint string   `json:"cloudflareIPv4Endpoint,omitempty"`
	CloudflareIPv6Endpoint string   `json:"cloudflareIPv6Endpoint,omitempty"`
	FastlyEndpoint         string   `json:"fastlyEndpoint,omitempty"`
	AWSIPRangesEndpoint    string   `json:"awsIpRangesEndpoint,omitempty"`
}

// Provider implements the Traefik plugin provider interface.
type Provider struct {
	name         string
	cfg          *Config
	pollInterval time.Duration
	errorHTML    string

	client *http.Client

	v4 *cidrtree.Tree
	v6 *cidrtree.Tree

	// Fetchers are injected to allow overriding in tests.
	fetchPlaintextCIDRs func(context.Context, *http.Client, string) ([]string, error)
	fetchFastlyRanges   func(context.Context, *http.Client, string) ([]string, []string, error)
	fetchAWSRanges      func(context.Context, *http.Client, string) ([]string, []string, error)

	mutex     sync.RWMutex
	lastCIDRs []string
	published bool

	cancel      context.CancelFunc
	wg          sync.WaitGroup
	errorServer *http.Server
	errorURL    string
}

// CreateConfig returns the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		PollInterval:           "5m",
		ErrorHTML:              errorHTMLDefault,
		AllowCloudflare:        true,
		AllowFastly:            true,
		AllowAWS:               true,
		CloudflareIPv4Endpoint: defaultCloudflareIPv4Endpoint,
		CloudflareIPv6Endpoint: defaultCloudflareIPv6Endpoint,
		FastlyEndpoint:         defaultFastlyEndpoint,
		AWSIPRangesEndpoint:    defaultAWSIPRangesEndpoint,
	}
}

// New creates a new provider instance.
func New(_ context.Context, cfg *Config, name string) (*Provider, error) {
	if cfg == nil {
		cfg = CreateConfig()
	}

	poll := parsePollInterval(cfg.PollInterval)
	if poll <= 0 {
		return nil, errors.New("poll interval must be positive")
	}

	html := strings.TrimSpace(cfg.ErrorHTML)
	if html == "" {
		html = errorHTMLDefault
	}

	if cfg.CloudflareIPv4Endpoint == "" {
		cfg.CloudflareIPv4Endpoint = defaultCloudflareIPv4Endpoint
	}
	if cfg.CloudflareIPv6Endpoint == "" {
		cfg.CloudflareIPv6Endpoint = defaultCloudflareIPv6Endpoint
	}
	if cfg.FastlyEndpoint == "" {
		cfg.FastlyEndpoint = defaultFastlyEndpoint
	}
	if cfg.AWSIPRangesEndpoint == "" {
		cfg.AWSIPRangesEndpoint = defaultAWSIPRangesEndpoint
	}

	return &Provider{
		name:         name,
		cfg:          cfg,
		pollInterval: poll,
		errorHTML:    html,
		client: &http.Client{
			Timeout: fetchTimeout,
		},
		v4: cidrtree.New(ipv4Bits),
		v6: cidrtree.New(ipv6Bits),

		fetchPlaintextCIDRs: fetchers.FetchPlaintextCIDRs,
		fetchFastlyRanges:   fetchers.FetchFastly,
		fetchAWSRanges:      fetchers.FetchAWSCloudFront,
	}, nil
}

// Init starts the internal HTTP server used for the HTML error response.
func (p *Provider) Init() error {
	return p.startErrorServer()
}

// Provide starts the background refresh loop and streams dynamic configs.
func (p *Provider) Provide(cfgChan chan<- json.Marshaler) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.run(ctx, cfgChan)
	}()

	return nil
}

// Stop halts background goroutines and the error server.
func (p *Provider) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}

	if p.errorServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := p.errorServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[cdn-whitelist] error server shutdown: %v", err)
		}
	}

	p.wg.Wait()
	return nil
}

func (p *Provider) run(ctx context.Context, cfgChan chan<- json.Marshaler) {
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()

	p.refreshAndPublish(ctx, cfgChan)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refreshAndPublish(ctx, cfgChan)
		}
	}
}

func (p *Provider) refreshAndPublish(parent context.Context, cfgChan chan<- json.Marshaler) {
	fetchCtx, cancel := context.WithTimeout(parent, fetchTimeout)
	defer cancel()

	cidrs, err := p.collectSources(fetchCtx)
	if err != nil {
		log.Printf("[cdn-whitelist] refresh failed: %v", err)
		return
	}

	changed := p.setCIDRs(cidrs)
	if !changed && p.published {
		return
	}

	config := p.buildConfiguration()
	cfgChan <- &dynamic.JSONPayload{Configuration: config}
	p.published = true
}

func (p *Provider) setCIDRs(cidrs []string) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if equalStringSlices(p.lastCIDRs, cidrs) {
		return false
	}

	p.lastCIDRs = cloneStringSlice(cidrs)
	return true
}

func (p *Provider) currentCIDRs() []string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return cloneStringSlice(p.lastCIDRs)
}

func (p *Provider) collectSources(ctx context.Context) ([]string, error) {
	v4 := cidrtree.New(ipv4Bits)
	v6 := cidrtree.New(ipv6Bits)

	var errs []error

	errs = p.appendCloudflareRanges(ctx, v4, v6, errs)
	errs = p.appendFastlyRanges(ctx, v4, v6, errs)
	errs = p.appendAWSRanges(ctx, v4, v6, errs)
	errs = p.appendAdditionalCIDRs(v4, v6, errs)

	cidrs := append(v4.CIDRs(), v6.CIDRs()...)
	sort.Strings(cidrs)

	if len(cidrs) == 0 {
		if len(errs) == 0 {
			return nil, errors.New("no CIDR ranges available")
		}
		return nil, errors.Join(errs...)
	}

	if len(errs) > 0 {
		log.Printf("[cdn-whitelist] partial refresh errors: %v", errors.Join(errs...))
	}

	return cidrs, nil
}

func (p *Provider) appendCloudflareRanges(
	ctx context.Context,
	v4, v6 *cidrtree.Tree,
	errs []error,
) []error {
	if !p.cfg.AllowCloudflare {
		return errs
	}

	if err := p.addPlaintext(ctx, v4, nil, p.cfg.CloudflareIPv4Endpoint); err != nil {
		errs = append(errs, fmt.Errorf("cloudflare ipv4: %w", err))
	}

	if err := p.addPlaintext(ctx, nil, v6, p.cfg.CloudflareIPv6Endpoint); err != nil {
		errs = append(errs, fmt.Errorf("cloudflare ipv6: %w", err))
	}

	return errs
}

func (p *Provider) appendFastlyRanges(
	ctx context.Context,
	v4, v6 *cidrtree.Tree,
	errs []error,
) []error {
	if !p.cfg.AllowFastly {
		return errs
	}

	v4Ranges, v6Ranges, err := p.fetchFastlyRanges(ctx, p.client, p.cfg.FastlyEndpoint)
	if err != nil {
		return append(errs, fmt.Errorf("fastly: %w", err))
	}

	addCIDRList(v4Ranges, v4, nil)
	addCIDRList(v6Ranges, nil, v6)

	return errs
}

func (p *Provider) appendAWSRanges(
	ctx context.Context,
	v4, v6 *cidrtree.Tree,
	errs []error,
) []error {
	if !p.cfg.AllowAWS {
		return errs
	}

	v4Ranges, v6Ranges, err := p.fetchAWSRanges(ctx, p.client, p.cfg.AWSIPRangesEndpoint)
	if err != nil {
		return append(errs, fmt.Errorf("aws: %w", err))
	}

	addCIDRList(v4Ranges, v4, nil)
	addCIDRList(v6Ranges, nil, v6)

	return errs
}

func (p *Provider) appendAdditionalCIDRs(
	v4, v6 *cidrtree.Tree,
	errs []error,
) []error {
	for _, cidr := range p.cfg.AdditionalCIDRs {
		if err := insertCIDR(strings.TrimSpace(cidr), v4, v6); err != nil {
			errs = append(errs, fmt.Errorf("additional %q: %w", cidr, err))
		}
	}

	return errs
}

func (p *Provider) addPlaintext(ctx context.Context, v4, v6 *cidrtree.Tree, endpoint string) error {
	cidrs, err := p.fetchPlaintextCIDRs(ctx, p.client, endpoint)
	if err != nil {
		return err
	}
	addCIDRList(cidrs, v4, v6)
	return nil
}

func addCIDRList(cidrs []string, v4, v6 *cidrtree.Tree) {
	for _, item := range cidrs {
		_ = insertCIDR(item, v4, v6)
	}
}

func insertCIDR(raw string, v4, v6 *cidrtree.Tree) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return err
	}

	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		if v4 == nil {
			return nil
		}
		v4.Insert(netip.PrefixFrom(addr, prefix.Bits()))
		return nil
	}

	if v6 == nil {
		return nil
	}

	v6.Insert(netip.PrefixFrom(addr, prefix.Bits()))
	return nil
}

func (p *Provider) buildConfiguration() *dynamic.Configuration {
	cidrs := p.currentCIDRs()

	httpConfig := &dynamic.HTTPConfiguration{
		Middlewares: map[string]*dynamic.Middleware{},
		Services:    map[string]*dynamic.Service{},
	}

	httpConfig.Middlewares[whitelistMiddlewareName] = &dynamic.Middleware{
		IPWhiteList: &dynamic.IPWhiteList{SourceRange: cidrs},
	}

	httpConfig.Middlewares[errorMiddlewareName] = &dynamic.Middleware{
		Errors: &dynamic.ErrorPage{
			Status:  []string{"401", "403"},
			Service: blockedServiceName,
			Query:   "/",
		},
	}

	httpConfig.Middlewares[chainMiddlewareName] = &dynamic.Middleware{
		Chain: &dynamic.Chain{Middlewares: []string{whitelistMiddlewareName, errorMiddlewareName}},
	}

	if p.errorURL != "" {
		httpConfig.Services[blockedServiceName] = &dynamic.Service{
			LoadBalancer: &dynamic.ServersLoadBalancer{
				Servers: []dynamic.Server{
					{URL: p.errorURL},
				},
				PassHostHeader: boolPtr(false),
			},
		}
	}

	return &dynamic.Configuration{HTTP: httpConfig}
}

func (p *Provider) startErrorServer() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start error server: %w", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, p.errorHTML)
		}),
		ReadHeaderTimeout: serverTimeout,
		WriteTimeout:      serverTimeout,
	}

	p.errorURL = "http://" + listener.Addr().String()
	p.errorServer = srv

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[cdn-whitelist] error server: %v", err)
		}
	}()

	return nil
}

func parsePollInterval(raw string) time.Duration {
	if strings.TrimSpace(raw) == "" {
		return defaultPollInterval
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		return defaultPollInterval
	}

	if d < minimumPollInterval {
		return minimumPollInterval
	}

	return d
}

func boolPtr(v bool) *bool {
	return &v
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}

	out := make([]string, len(in))
	copy(out, in)
	return out
}
