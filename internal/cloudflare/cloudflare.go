package cloudflare

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	apiToken string
	email    string
	mu       sync.RWMutex
	zones    []string
	fetched  time.Time
	cacheTTL time.Duration
}

type zonesResponse struct {
	Success bool   `json:"success"`
	Result  []zone `json:"result"`
}

type zone struct {
	Name string `json:"name"`
}

func NewClient(apiToken, email string) *Client {
	return &Client{apiToken: apiToken, email: email, cacheTTL: 5 * time.Minute}
}

func (c *Client) Configured() bool { return c.apiToken != "" }

func (c *Client) GetZones() ([]string, error) {
	if !c.Configured() {
		return nil, nil
	}
	c.mu.RLock()
	if time.Since(c.fetched) < c.cacheTTL && c.zones != nil {
		defer c.mu.RUnlock()
		result := make([]string, len(c.zones))
		copy(result, c.zones)
		return result, nil
	}
	c.mu.RUnlock()

	zones, err := c.fetchZones()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.zones = zones
	c.fetched = time.Now()
	c.mu.Unlock()

	result := make([]string, len(zones))
	copy(result, zones)
	return result, nil
}

func (c *Client) fetchZones() ([]string, error) {
	req, err := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones?per_page=50&status=active", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	if c.email != "" {
		req.Header.Set("X-Auth-Email", c.email)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare API status %d", resp.StatusCode)
	}

	var result zonesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if !result.Success {
		return nil, fmt.Errorf("cloudflare API success=false")
	}

	var zones []string
	for _, z := range result.Result {
		zones = append(zones, z.Name)
	}
	return zones, nil
}

func (c *Client) InvalidateCache() {
	c.mu.Lock()
	c.zones = nil
	c.fetched = time.Time{}
	c.mu.Unlock()
}
