package auth

import (
	"context"
	"fmt"
	"strings"

	kagentauth "github.com/kagent-dev/kagent/go/pkg/auth"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type K8sRBACAuthorizer struct {
	kubeClient client.Client
}

func NewK8sRBACAuthorizer(kubeClient client.Client) *K8sRBACAuthorizer {
	return &K8sRBACAuthorizer{kubeClient: kubeClient}
}

func (a *K8sRBACAuthorizer) Check(ctx context.Context, principal kagentauth.Principal, verb kagentauth.Verb, resource kagentauth.Resource) error {
	group, res, namespace, name, err := mapResource(resource)
	if err != nil {
		return err
	}

	// If the resource is namespaced but the caller didn't provide a namespace (common for list endpoints),
	// default to the selected namespace from the HTTP layer.
	if namespace == "" && resource.Type != "Namespace" {
		if selectedNS, ok := kagentauth.SelectedNamespaceFrom(ctx); ok {
			namespace = selectedNS
		}
	}

	// The HTTP layer maps GET requests to VerbGet.
	// For collection endpoints (no object name), Kubernetes RBAC expects "list".
	sarVerb := string(verb)
	if verb == kagentauth.VerbGet && name == "" {
		sarVerb = "list"
	}

	sar := &authzv1.SubjectAccessReview{
		ObjectMeta: metav1.ObjectMeta{},
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   principal.User.ID,
			Groups: principal.User.Roles,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:      sarVerb,
				Group:     group,
				Resource:  res,
				Namespace: namespace,
				Name:      name,
			},
		},
	}

	if err := a.kubeClient.Create(ctx, sar); err != nil {
		return fmt.Errorf("rbac check failed: %w", err)
	}
	if !sar.Status.Allowed {
		denied := sar.Status.Reason
		if denied == "" {
			denied = "not allowed"
		}
		return fmt.Errorf("rbac denied: %s", denied)
	}
	return nil
}

func mapResource(r kagentauth.Resource) (group string, resource string, namespace string, name string, err error) {
	if r.Type == "" {
		return "", "", "", "", fmt.Errorf("missing resource type")
	}

	// Parse "namespace/name" when present.
	if r.Name != "" {
		parts := strings.Split(r.Name, "/")
		if len(parts) == 2 {
			namespace = parts[0]
			name = parts[1]
		} else {
			name = r.Name
		}
	}

	switch r.Type {
	case "Agent":
		return "kagent.dev", "agents", namespace, name, nil
	case "ModelConfig":
		return "kagent.dev", "modelconfigs", namespace, name, nil
	case "ToolServer":
		return "kagent.dev", "toolservers", namespace, name, nil
	case "Memory":
		return "kagent.dev", "memories", namespace, name, nil
	case "RemoteMCPServer":
		return "kagent.dev", "remotemcpservers", namespace, name, nil
	case "MCPServer":
		return "kagent.dev", "mcpservers", namespace, name, nil
	case "Namespace":
		return "", "namespaces", "", name, nil
	default:
		return "", "", "", "", fmt.Errorf("unsupported resource type for authz: %s", r.Type)
	}
}

var _ kagentauth.Authorizer = (*K8sRBACAuthorizer)(nil)
