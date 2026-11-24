package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	proxyRequestTimeout   = 30 * time.Second
	proxyPollInterval     = time.Second
	maxProxyResponseBytes = 4 << 20
)

type proxyMirrorClient struct {
	baseURL *url.URL
	http    *http.Client
}

type proxyMirrorJob struct {
	State    string `json:"state"`
	Error    string `json:"error"`
	Progress struct {
		Total     int64 `json:"total"`
		Completed int64 `json:"completed"`
		Skipped   int64 `json:"skipped"`
		Failed    int64 `json:"failed"`
		Errors    []struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Version   string `json:"version"`
			Error     string `json:"error"`
		} `json:"errors"`
	} `json:"progress"`
}

func (job proxyMirrorJob) summary() string {
	return fmt.Sprintf("%s: %d downloaded, %d already cached, %d failed (%d total)",
		Sanitize(job.State), job.Progress.Completed, job.Progress.Skipped, job.Progress.Failed, job.Progress.Total)
}

func newProxyMirrorClient(baseURL string) (*proxyMirrorClient, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("provide --url or set PROXY_URL")
	}
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("proxy URL must be an HTTP(S) base URL without credentials, query, or fragment")
	}
	return &proxyMirrorClient{
		baseURL: u,
		http: &http.Client{
			Timeout:       proxyRequestTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (client *proxyMirrorClient) start(ctx context.Context, purls []string) (string, error) {
	body, err := json.Marshal(struct {
		PURLs []string `json:"purls"`
	}{purls})
	if err != nil {
		return "", err
	}
	var result struct {
		ID string `json:"id"`
	}
	if err := client.request(ctx, http.MethodPost, "", body, http.StatusAccepted, &result); err != nil {
		return "", fmt.Errorf("starting mirror job: %w", err)
	}
	if result.ID == "" || strings.ContainsAny(result.ID, "/?#") || result.ID == "." || result.ID == ".." {
		return "", fmt.Errorf("proxy returned an invalid mirror job ID")
	}
	return result.ID, nil
}

func (client *proxyMirrorClient) wait(ctx context.Context, id string, progress func(string)) (*proxyMirrorJob, error) {
	ticker := time.NewTicker(proxyPollInterval)
	defer ticker.Stop()
	lastStatus := ""
	for {
		var job proxyMirrorJob
		if err := client.request(ctx, http.MethodGet, id, nil, http.StatusOK, &job); err != nil {
			return nil, err
		}
		switch job.State {
		case "complete", "failed", "canceled":
			return &job, nil
		case "pending", "running":
			if status := job.summary(); status != lastStatus {
				progress(status)
				lastStatus = status
			}
		default:
			return nil, fmt.Errorf("proxy returned unknown mirror job state %q", Sanitize(job.State))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (client *proxyMirrorClient) request(ctx context.Context, method, id string, body []byte, status int, result any) error {
	u := client.baseURL.JoinPath("api", "mirror")
	if id != "" {
		u = u.JoinPath(id)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != status {
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("proxy returned HTTP 404; check the URL, enable mirror_api on the proxy, and check whether the job expired")
		}
		return fmt.Errorf("proxy returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxProxyResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxProxyResponseBytes {
		return fmt.Errorf("proxy response exceeds size limit")
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("invalid proxy response: %w", err)
	}
	return nil
}
