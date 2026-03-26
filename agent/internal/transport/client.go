package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
)

type Client struct {
	url string
}

func NewClient(url string) *Client {
	return &Client{url: url}
}

func (c *Client) Send(ctx context.Context, event any) error {
	payload := map[string]any{
		"payload": event,
	}

	body, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	_, err := http.DefaultClient.Do(req)
	return err
}
