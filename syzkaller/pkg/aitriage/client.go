// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aitriage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
)

// LLMClient provides a unified interface for LLM API calls.
type LLMClient interface {
	Chat(ctx context.Context, systemPrompt, userPrompt string) (*LLMResponse, error)
}

type LLMResponse struct {
	Content      string
	InputTokens  int
	OutputTokens int
}

func NewClient(cfg mgrconfig.AITriageConfig) (LLMClient, error) {
	provider := cfg.Provider
	if provider == "" {
		if strings.HasPrefix(cfg.Model, "claude-") {
			provider = "anthropic"
		} else {
			provider = "openai"
		}
	}
	switch provider {
	case "anthropic":
		baseURL := cfg.APIURL
		if baseURL == "" {
			baseURL = "https://api.anthropic.com"
		}
		return &anthropicClient{
			apiKey:  cfg.APIKey,
			model:   cfg.Model,
			baseURL: baseURL,
		}, nil
	case "openai":
		baseURL := cfg.APIURL
		if baseURL == "" {
			baseURL = "https://api.openai.com"
		}
		return &openaiClient{
			apiKey:  cfg.APIKey,
			model:   cfg.Model,
			baseURL: baseURL,
		}, nil
	default:
		return nil, fmt.Errorf("unknown AI provider: %v", provider)
	}
}

// --- Anthropic Client ---

type anthropicClient struct {
	apiKey  string
	model   string
	baseURL string
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	System      string             `json:"system"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (c *anthropicClient) Chat(ctx context.Context, systemPrompt, userPrompt string) (*LLMResponse, error) {
	reqBody := anthropicRequest{
		Model:       c.model,
		MaxTokens:   4096,
		Temperature: 0.2,
		System:      systemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userPrompt},
		},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	var resp anthropicResponse
	err = doRequestWithRetry(ctx, c.baseURL+"/v1/messages", data, map[string]string{
		"x-api-key":         c.apiKey,
		"anthropic-version":  "2023-06-01",
		"content-type":       "application/json",
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("anthropic API error: %v", resp.Error.Message)
	}
	if len(resp.Content) == 0 {
		return nil, fmt.Errorf("anthropic returned empty content")
	}
	return &LLMResponse{
		Content:      resp.Content[0].Text,
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
	}, nil
}

// --- OpenAI Client ---

type openaiClient struct {
	apiKey  string
	model   string
	baseURL string
}

type openaiRequest struct {
	Model       string           `json:"model"`
	MaxTokens   int              `json:"max_tokens"`
	Temperature float64          `json:"temperature"`
	Messages    []openaiMessage  `json:"messages"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (c *openaiClient) Chat(ctx context.Context, systemPrompt, userPrompt string) (*LLMResponse, error) {
	reqBody := openaiRequest{
		Model:       c.model,
		MaxTokens:   4096,
		Temperature: 0.2,
		Messages: []openaiMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
	}
	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	var resp openaiResponse
	err = doRequestWithRetry(ctx, c.baseURL+"/v1/chat/completions", data, map[string]string{
		"Authorization": "Bearer " + c.apiKey,
		"Content-Type":  "application/json",
	}, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("openai API error: %v", resp.Error.Message)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("openai returned no choices")
	}
	return &LLMResponse{
		Content:      resp.Choices[0].Message.Content,
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}, nil
}

// --- Shared HTTP helper with retry ---

func doRequestWithRetry(ctx context.Context, url string, body []byte, headers map[string]string, result any) error {
	client := &http.Client{Timeout: 60 * time.Second}
	backoffs := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}

	var lastErr error
	for attempt := 0; attempt <= 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoffs[attempt-1]):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
			continue
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}

		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
		return nil
	}
	return fmt.Errorf("all retries failed: %w", lastErr)
}
