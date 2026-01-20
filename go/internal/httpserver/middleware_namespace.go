package httpserver

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/kagent-dev/kagent/go/internal/httpserver/errors"
	"github.com/kagent-dev/kagent/go/internal/httpserver/handlers"
	"github.com/kagent-dev/kagent/go/pkg/auth"
)

const selectedNamespaceHeader = "X-Kagent-Namespace"

// namespaceSelectionMiddleware enforces a user-selected namespace for all namespaced operations.
//
// Rules:
// - /api/namespaces does not require a selected namespace (so users can switch).
// - Other /api endpoints require X-Kagent-Namespace.
// - If a route has a {namespace} path param, it must match the selected namespace.
// - The selected namespace is stored in request context for handlers to use when listing/creating.
func namespaceSelectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		erw, ok := w.(handlers.ErrorResponseWriter)
		if !ok {
			// Fallback to plain errors if middleware ordering is unexpected.
			erw = nil
		}

		if r.URL == nil {
			next.ServeHTTP(w, r)
			return
		}

		path := r.URL.Path
		if !strings.HasPrefix(path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if path == "/api/namespaces" {
			next.ServeHTTP(w, r)
			return
		}

		sel := strings.TrimSpace(r.Header.Get(selectedNamespaceHeader))
		if sel == "" {
			if erw != nil {
				erw.RespondWithError(errors.NewBadRequestError("Missing selected namespace", nil))
				return
			}
			http.Error(w, "Missing selected namespace", http.StatusBadRequest)
			return
		}

		if vars := mux.Vars(r); vars != nil {
			if pathNS, ok := vars["namespace"]; ok && pathNS != "" && pathNS != sel {
				if erw != nil {
					erw.RespondWithError(errors.NewForbiddenError("Namespace does not match selected namespace", nil))
					return
				}
				http.Error(w, "Namespace does not match selected namespace", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r.WithContext(auth.SelectedNamespaceTo(r.Context(), sel)))
	})
}
