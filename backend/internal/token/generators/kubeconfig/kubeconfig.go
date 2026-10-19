package kubeconfig

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"text/template"

	"canary-token-generator/backend/internal/token"
	"canary-token-generator/backend/internal/token/generators/seed"
)

const KubeconfigTemplate = `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: {{ .ClusterEndpoint }}
    insecure-skip-tls-verify: true
  name: prod-k8s-cluster
contexts:
- context:
    cluster: prod-k8s-cluster
    user: cluster-admin-user
    namespace: kube-system
  name: prod-admin-context
current-context: prod-admin-context
users:
- name: cluster-admin-user
  user:
    token: {{ .BearerToken }}
`

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() string { return "kubeconfig" }

type TemplateData struct {
	ClusterEndpoint string
	BearerToken     string
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// FakeServiceAccountJWT genera un JWT con cabecera y carga utiles en base64url REALES (claims de una
// service account de Kubernetes) y una "firma" de 256 bytes. Antes el segmento central era el ID en
// bruto y la firma el literal "k8s-admin-signature": cualquier atacante que lo decodificara veia que era falso.
func FakeServiceAccountJWT(s *seed.Stream, tokenID string) string {
	hdr := b64(map[string]string{"alg": "RS256", "kid": s.Pick(seed.Base64URL, 43)})
	uid := fmt.Sprintf("%x-%x-%x-%x-%x", s.Bytes(4), s.Bytes(2), s.Bytes(2), s.Bytes(2), s.Bytes(6))
	payload := b64(map[string]any{
		"iss":                                    "kubernetes/serviceaccount",
		"kubernetes.io/serviceaccount/namespace": "kube-system",
		"kubernetes.io/serviceaccount/secret.name":          "cluster-admin-token-" + s.Pick("bcdfghjklmnpqrstvwxz2456789", 5),
		"kubernetes.io/serviceaccount/service-account.name": "cluster-admin",
		"kubernetes.io/serviceaccount/service-account.uid":  uid,
		"sub": "system:serviceaccount:kube-system:cluster-admin",
		"jti": tokenID, // permite atribuir el uso aunque se pierda la ruta /k/<id>
	})
	return hdr + "." + payload + "." + base64.RawURLEncoding.EncodeToString(s.Bytes(256))
}

func (g *Generator) Generate(ctx context.Context, req token.GenerateRequest) (*token.GenerateResult, error) {
	clusterEndpoint := fmt.Sprintf("%s/k/%s", req.Base(), req.TokenID)
	jwt := FakeServiceAccountJWT(seed.New(req.Seed, "kubeconfig"), req.TokenID)

	tmpl, err := template.New("kubeconfig").Parse(KubeconfigTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, TemplateData{ClusterEndpoint: clusterEndpoint, BearerToken: jwt}); err != nil {
		return nil, fmt.Errorf("failed to execute kubeconfig template: %w", err)
	}

	fileName := fmt.Sprintf("kubeconfig_%s.yaml", req.TokenID[:8])
	return &token.GenerateResult{
		Artifact:     buf.Bytes(),
		ArtifactName: fileName,
		ContentType:  "application/x-yaml",
		Snippet:      buf.String(),
		Instructions: "Place this fake kubeconfig in ~/.kube/config on bastion hosts, CI runners or developer machines. Any kubectl/API call made " +
			"with it reaches this server, which records the caller and answers 401 without revealing that it is a decoy.",
		Metadata: map[string]any{"filename": fileName, "cluster_endpoint": clusterEndpoint},
	}, nil
}
