# 04 — Kubeconfig & K8s Canaries

## The Threat Landscape: Stolen Cloud Credentials

In modern cloud environments, Kubernetes cluster configurations (`~/.kube/config`) are among the most sought-after assets by attackers:
- They are frequently left unencrypted in home directories.
- They are stored in CI/CD runner environments (GitHub Actions, GitLab CI, Jenkins).
- Compromised developer workstations often have cluster-admin access cached.

---

## How `kubectl` Interacts with API Servers

When an attacker discovers a `kubeconfig` file, their immediate reflex is to test access:
```bash
kubectl get nodes
kubectl get pods -A
kubectl cluster-info
```

Under the hood, `client-go` (the Go library powering `kubectl`) issues several HTTP requests in parallel before running commands:
1. `GET /version` (Discovery probe to determine server API compatibility)
2. `GET /api` (Core API group discovery)
3. `GET /apis` (Named API groups discovery)
4. `GET /api/v1/namespaces/default/pods` (The requested resource query)

Every request includes the Authorization header:
```http
Authorization: Bearer <TOKEN>
User-Agent: kubectl/v1.28.2 (linux/amd64) kubernetes/890b139
```

---

## The Wildcard Canary Handler

Our backend mounts a wildcard HTTP route:
```go
r.HandleFunc("/k/{tokenID}/*", tokenHandler.KubeWildcard)
r.HandleFunc("/k/{tokenID}", tokenHandler.KubeWildcard)
```

In the generated `kubeconfig.yaml`, the cluster server is configured as:
```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://canary.domain.com/k/c4f92d8e1a7b
    insecure-skip-tls-verify: true
  name: prod-k8s-cluster
contexts:
- context:
    cluster: prod-k8s-cluster
    user: cluster-admin-user
  name: production-admin
current-context: production-admin
users:
- name: cluster-admin-user
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.c4f92d8e1a7b.k8s-admin-signature
```

---

## Interception and Deception Response

When `kubectl` touches `https://canary.domain.com/k/c4f92d8e1a7b/version`:

1. The Chi router matches `{tokenID}` = `c4f92d8e1a7b`.
2. The handler extracts:
   - Client IP (direct or via `CF-Connecting-IP`)
   - `User-Agent` (identifying the exact version and OS of the attacker's `kubectl` CLI)
   - The Authorization token provided
   - The specific resource requested (`/api/v1/pods`, `/apis`, etc.)
3. It triggers the event pipeline and sends immediate SIEM / Telegram alerts.
4. To maintain stealth, it responds with standard Kubernetes API error JSON:

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "Unauthorized: Invalid bearer token",
  "reason": "Unauthorized",
  "code": 401
}
```

The attacker sees:
```text
error: You must be logged in to the server (Unauthorized)
```
They conclude the cluster credentials expired or were rotated, unaware that their reconnaissance attempt was recorded and alerted in real-time.
