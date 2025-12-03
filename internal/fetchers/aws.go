// Package fetchers contains helper functions to download CDN IP ranges.
package fetchers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type awsIPRanges struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"` //nolint:tagliatelle // AWS API uses snake_case
		Service  string `json:"service"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix string `json:"ipv6_prefix"` //nolint:tagliatelle // AWS API uses snake_case
		Service    string `json:"service"`
	} `json:"ipv6_prefixes"` //nolint:tagliatelle // AWS API uses snake_case
}

// FetchAWSCloudFront returns IPv4/IPv6 ranges for the CloudFront service.
func FetchAWSCloudFront(ctx context.Context, client *http.Client, endpoint string) ([]string, []string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("get aws ranges: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("aws endpoint returned %s", resp.Status)
	}

	var data awsIPRanges
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, nil, fmt.Errorf("decode aws payload: %w", err)
	}

	var v4 []string
	var v6 []string
	for _, prefix := range data.Prefixes {
		if prefix.Service == "CLOUDFRONT" {
			v4 = append(v4, prefix.IPPrefix)
		}
	}
	for _, prefix := range data.IPv6Prefixes {
		if prefix.Service == "CLOUDFRONT" {
			v6 = append(v6, prefix.IPv6Prefix)
		}
	}

	return v4, v6, nil
}
