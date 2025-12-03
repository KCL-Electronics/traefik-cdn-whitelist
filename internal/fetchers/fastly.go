package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type fastlyResponse struct {
	Addresses     []string `json:"addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"` //nolint:tagliatelle // Fastly API uses snake_case
}

// FetchFastly returns IPv4/IPv6 ranges published by Fastly.
func FetchFastly(ctx context.Context, client *http.Client, endpoint string) ([]string, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("get fastly ranges: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("fastly endpoint returned %s", resp.Status)
	}

	var data fastlyResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil, fmt.Errorf("decode fastly payload: %w", err)
	}

	return data.Addresses, data.IPv6Addresses, nil
}
