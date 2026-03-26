package http

import (
	"encoding/json"
	"net/http"

	"edr-platform/api-server/internal/model"
	"edr-platform/api-server/internal/service"
)

type Handler struct {
	alertService    *service.AlertService
	incidentService *service.IncidentService // ✅ ADD
}

func NewHandler(alertService *service.AlertService, incidentService *service.IncidentService) *Handler {
	return &Handler{
		alertService:    alertService,
		incidentService: incidentService,
	}
}

func (h *Handler) GetAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	alerts, err := h.alertService.ListAlerts(r.Context(), model.AlertFilters{})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	json.NewEncoder(w).Encode(alerts)
}

// ✅ NEW
func (h *Handler) GetIncidents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	incidents, err := h.incidentService.ListIncidents(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	json.NewEncoder(w).Encode(incidents)
}
