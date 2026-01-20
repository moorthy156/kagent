package handlers

import (
	"net/http"
	"strings"

	"github.com/kagent-dev/kagent/go/internal/database"
	"github.com/kagent-dev/kagent/go/internal/httpserver/errors"
	"github.com/kagent-dev/kagent/go/pkg/client/api"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// ToolsHandler handles tool-related requests
type ToolsHandler struct {
	*Base
}

// NewToolsHandler creates a new ToolsHandler
func NewToolsHandler(base *Base) *ToolsHandler {
	return &ToolsHandler{Base: base}
}

// HandleListTools handles GET /api/tools requests using database
func (h *ToolsHandler) HandleListTools(w ErrorResponseWriter, r *http.Request) {
	log := ctrllog.FromContext(r.Context()).WithName("tools-handler").WithValues("operation", "list-db")

	selectedNS, err := GetSelectedNamespace(r)
	if err != nil {
		w.RespondWithError(errors.NewBadRequestError("Missing selected namespace", err))
		return
	}
	log = log.WithValues("selectedNamespace", selectedNS)

	userID, err := GetUserID(r)
	if err != nil {
		w.RespondWithError(errors.NewBadRequestError("Failed to get user ID", err))
		return
	}
	log = log.WithValues("userID", userID)

	log.V(1).Info("Listing tools from database")
	tools, err := h.DatabaseService.ListTools()
	if err != nil {
		w.RespondWithError(errors.NewInternalServerError("Failed to list tools", err))
		return
	}

	filtered := make([]database.Tool, 0, len(tools))
	for _, t := range tools {
		if strings.HasPrefix(t.ServerName, selectedNS+"/") {
			filtered = append(filtered, t)
		}
	}

	log.Info("Successfully listed tools", "count", len(filtered))
	data := api.NewResponse(filtered, "Successfully listed tools", false)
	RespondWithJSON(w, http.StatusOK, data)
}
