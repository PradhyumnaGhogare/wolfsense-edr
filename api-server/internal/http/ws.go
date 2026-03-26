package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// writeJSON is a helper for writing JSON responses.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if payload == nil {
		return
	}

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("failed to write json response", "error", err)
	}
}

// writeError is a helper for writing JSON error responses.
func writeError(w http.ResponseWriter, status int, message string) {
	type ErrorResponse struct {
		Error string `json:"error"`
	}
	writeJSON(w, status, ErrorResponse{Error: message})
}
