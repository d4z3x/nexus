package adguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

type Filter struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type FilteringStatus struct {
	Filters          []Filter `json:"filters"`
	WhitelistFilters []Filter `json:"whitelist_filters"`
	UserRules        []string `json:"user_rules"`
	Enabled          bool     `json:"enabled"`
	Interval         int      `json:"interval"`
}

type Client struct {
	BaseURL    string
	Username   string
	Password   string
	httpClient *http.Client
}

func NewClient(baseURL, username, password string) *Client {
	return &Client{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) Configured() bool {
	return c.BaseURL != ""
}

func (c *Client) doRequest(method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (c *Client) ListRewrites() ([]Rewrite, error) {
	data, err := c.doRequest(http.MethodGet, "/control/rewrite/list", nil)
	if err != nil {
		return nil, fmt.Errorf("list rewrites: %w", err)
	}

	var rewrites []Rewrite
	if err := json.Unmarshal(data, &rewrites); err != nil {
		return nil, fmt.Errorf("decode rewrites: %w", err)
	}
	return rewrites, nil
}

func (c *Client) AddRewrite(r Rewrite) error {
	_, err := c.doRequest(http.MethodPost, "/control/rewrite/add", r)
	if err != nil {
		return fmt.Errorf("add rewrite %s -> %s: %w", r.Domain, r.Answer, err)
	}
	return nil
}

func (c *Client) DeleteRewrite(r Rewrite) error {
	_, err := c.doRequest(http.MethodPost, "/control/rewrite/delete", r)
	if err != nil {
		return fmt.Errorf("delete rewrite %s -> %s: %w", r.Domain, r.Answer, err)
	}
	return nil
}

func (c *Client) GetFilteringStatus() (*FilteringStatus, error) {
	data, err := c.doRequest(http.MethodGet, "/control/filtering/status", nil)
	if err != nil {
		return nil, fmt.Errorf("get filtering status: %w", err)
	}

	var status FilteringStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("decode filtering status: %w", err)
	}
	return &status, nil
}

func (c *Client) AddFilter(name, url string, whitelist bool) error {
	_, err := c.doRequest(http.MethodPost, "/control/filtering/add_url", map[string]interface{}{
		"name":      name,
		"url":       url,
		"whitelist": whitelist,
	})
	if err != nil {
		return fmt.Errorf("add filter %s: %w", name, err)
	}
	return nil
}

func (c *Client) RemoveFilter(url string, whitelist bool) error {
	_, err := c.doRequest(http.MethodPost, "/control/filtering/remove_url", map[string]interface{}{
		"url":       url,
		"whitelist": whitelist,
	})
	if err != nil {
		return fmt.Errorf("remove filter %s: %w", url, err)
	}
	return nil
}

func (c *Client) SetUserRules(rules []string) error {
	_, err := c.doRequest(http.MethodPost, "/control/filtering/set_rules", map[string]interface{}{
		"rules": rules,
	})
	if err != nil {
		return fmt.Errorf("set user rules: %w", err)
	}
	return nil
}
