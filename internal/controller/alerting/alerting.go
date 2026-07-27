package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type AlertLevel string

const (
	AlertLevelInfo    AlertLevel = "info"
	AlertLevelWarning AlertLevel = "warning"
	AlertLevelError   AlertLevel = "error"
)

type Alert struct {
	Level       AlertLevel
	Source      string
	Message     string
	Detail      map[string]any
	Timestamp   time.Time
}

type WebhookConfig struct {
	URL        string
	Secret     string
	Timeout    time.Duration
}

type Notifier struct {
	log      *slog.Logger
	webhooks []WebhookConfig
	client   *http.Client
	mu       sync.Mutex
}

func New(log *slog.Logger, configs []WebhookConfig) *Notifier {
	return &Notifier{
		log:      log,
		webhooks: configs,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (n *Notifier) Send(ctx context.Context, alert Alert) {
	if len(n.webhooks) == 0 {
		return
	}

	n.mu.Lock()
	webhooks := make([]WebhookConfig, len(n.webhooks))
	copy(webhooks, n.webhooks)
	n.mu.Unlock()

	for _, cfg := range webhooks {
		go n.sendToWebhook(ctx, cfg, alert)
	}
}

func (n *Notifier) sendToWebhook(ctx context.Context, cfg WebhookConfig, alert Alert) {
	payload := map[string]any{
		"level":     alert.Level,
		"source":    alert.Source,
		"message":   alert.Message,
		"detail":    alert.Detail,
		"timestamp": alert.Timestamp.Format(time.RFC3339),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		n.log.Error("marshal alert payload", "err", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(data))
	if err != nil {
		n.log.Error("create webhook request", "err", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if cfg.Secret != "" {
		req.Header.Set("X-Webhook-Secret", cfg.Secret)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Error("send webhook", "url", cfg.URL, "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		n.log.Warn("webhook response", "url", cfg.URL, "status", resp.StatusCode)
	}
}

func (n *Notifier) AddWebhook(cfg WebhookConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.webhooks = append(n.webhooks, cfg)
}

func (n *Notifier) RemoveWebhook(targetURL string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, wh := range n.webhooks {
		if wh.URL == targetURL {
			n.webhooks = append(n.webhooks[:i], n.webhooks[i+1:]...)
			return
		}
	}
}

func (n *Notifier) Webhooks() []WebhookConfig {
	n.mu.Lock()
	defer n.mu.Unlock()
	result := make([]WebhookConfig, len(n.webhooks))
	copy(result, n.webhooks)
	return result
}

func NewAlert(level AlertLevel, source, message string, detail map[string]any) Alert {
	return Alert{
		Level:     level,
		Source:    source,
		Message:   message,
		Detail:    detail,
		Timestamp: time.Now().UTC(),
	}
}

func NewDriftAlert(nodeID, expectedHash, actualHash string) Alert {
	return NewAlert(
		AlertLevelError,
		fmt.Sprintf("node/%s", nodeID),
		"检测到规则漂移",
		map[string]any{
			"node_id":        nodeID,
			"expected_hash":  expectedHash,
			"actual_hash":    actualHash,
		},
	)
}

func NewNodeOfflineAlert(nodeID string) Alert {
	return NewAlert(
		AlertLevelWarning,
		fmt.Sprintf("node/%s", nodeID),
		"节点离线",
		map[string]any{
			"node_id": nodeID,
		},
	)
}

func NewApplyFailedAlert(nodeID, taskID string, errorMsg string) Alert {
	return NewAlert(
		AlertLevelError,
		fmt.Sprintf("node/%s", nodeID),
		"策略应用失败",
		map[string]any{
			"node_id":  nodeID,
			"task_id":  taskID,
			"error":    errorMsg,
		},
	)
}