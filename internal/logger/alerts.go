package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// AlertHandler manages outgoing notifications.
type AlertHandler struct {
	webhookURL string
	client     *http.Client
}

// NewAlertHandler creates a new handler for Discord alerts.
func NewAlertHandler(url string) *AlertHandler {
	if url == "" {
		return nil
	}
	return &AlertHandler{
		webhookURL: url,
		client:     &http.Client{Timeout: 5 * time.Second},
	}
}

// SendCriticalAlert sends a formatted alert to Discord.
func (a *AlertHandler) SendCriticalAlert(sessionID int64, ip, country string, score int, pattern string) {
	if a == nil {
		return
	}

	content := fmt.Sprintf("🚨 **CRITICAL THREAT DETECTED** 🚨\n"+
		"**Session ID:** `%d`\n"+
		"**IP Address:** `%s` (%s)\n"+
		"**Threat Score:** `%d/100`\n"+
		"**Pattern:** `%s`\n"+
		"**Time:** %s",
		sessionID, ip, country, score, pattern, time.Now().UTC().Format(time.RFC822))

	payload := map[string]string{"content": content}
	data, _ := json.Marshal(payload)

	resp, err := a.client.Post(a.webhookURL, "application/json", bytes.NewBuffer(data))
	if err == nil {
		resp.Body.Close()
	}
}
