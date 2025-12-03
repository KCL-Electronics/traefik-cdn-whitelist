// Package fetchers contains helper functions to download CDN IP ranges.
package fetchers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// FetchPlaintextCIDRs downloads newline-delimited CIDR ranges from endpoint.
func FetchPlaintextCIDRs(ctx context.Context, client *http.Client, endpoint string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get ranges: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("endpoint %s returned %s", endpoint, resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	var cidrs []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidrs = append(cidrs, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan response: %w", err)
	}

	return cidrs, nil
}
