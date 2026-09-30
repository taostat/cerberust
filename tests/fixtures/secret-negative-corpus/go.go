package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

type Client struct {
	baseURL string
	token   string
	timeout time.Duration
}

func New() (*Client, error) {
	token := os.Getenv("STORE_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("STORE_TOKEN is not set")
	}
	return &Client{baseURL: "https://store.internal", token: token, timeout: 10 * time.Second}, nil
}

func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	// object key example: objects/81/1578a82b1cfd4649aeed1c31b35ee7bff0c6a8c31b8f5e83f1d18b2a641412
	return nil, nil
}

var knownGood = map[string]string{
	"v1.2.3": "0813dd6454f5e89f9abab5b3a3f328d4d90fe0004b5a7fe6c303d2605c8483df",
	"v1.2.4": "98f2272bcf355fb27bcae935fd001d1df84759fca5605cb96f9fabbaf61cf702",
}
