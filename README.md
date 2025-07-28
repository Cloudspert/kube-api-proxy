# kube-api-proxy

`kube-api-proxy` sets up **nftables DNAT rules** to redirect Kubernetes API traffic from the internal cluster IP (e.g., `10.0.0.1`) to a **load balancer/public IP** (e.g., `34.x.x.x`).  
This is useful in **hosted control plane** environments where the API server is not directly reachable from the pod network.

---

## 🚀 How It Works

- Pods communicate with the API server via the default internal IP (e.g., `10.0.0.1`)
- `kube-api-proxy` adds **nftables DNAT rules** on the node
- These rules **rewrite the destination IP** to the public or load balancer IP
- Traffic reaches the remote API server transparently
- No restart is required

---

## 🛠️ Installation

### Prerequisites

- Kubernetes cluster with **hosted or remote API server**
- Helm 3.x
- Privileged permissions to run `nftables` (host networking)

### Add Helm Repo

```bash
helm repo add kube-api-proxy https://cloudspert.github.io/kube-api-proxy/
helm repo update
```

### Install with Custom Values

```bash
helm install kube-api-proxy kube-api-proxy/kube-api-proxy \
  --set listenIP=10.0.0.1 \
  --set targetLoadBalancer=34.67.12.9
```

### Upgrade

```bash
helm upgrade kube-api-proxy kube-api-proxy/kube-api-proxy \
  --set listenIP=<updated-ip> \
  --set targetLoadBalancer=<updated-lb-ip>
```

---

## ⚙️ Configuration

Set values via `--set` or in `values.yaml`.

| Parameter              | Description                                              | Example        |
|------------------------|----------------------------------------------------------|----------------|
| `listenIP`             | Internal API IP to match (e.g., service IP)              | `10.0.0.1`     |
| `targetLoadBalancer`   | Public IP of kube-apiserver/load balancer                | `34.67.12.9`   |
| `listenPort`           | Optional; port to match on (default: `6443`)             | `443`          |
| `resources`            | CPU/memory requests and limits                           | `{}`           |
| `nodeSelector`         | Schedule only to certain nodes                           | `{}`           |
| `tolerations`          | Tolerate taints for control plane or system nodes        | `[]`           |

---

## 🧪 Development

### Clone and Build

```bash
git clone https://github.com/Cloudspert/kube-api-proxy.git
cd kube-api-proxy
go build
```

### Test Helm Locally

```bash
helm install test ./helm/kube-api-proxy \
  --set listenIP=10.0.0.1 \
  --set targetLoadBalancer=34.67.12.9
```

### Cleanup

```bash
helm uninstall kube-api-proxy
```

> The Helm chart manages nftables rules dynamically. Rules are removed automatically when the Pod terminates.

---

## 🛡️ Notes

- Runs in **privileged mode** to manage `nftables` rules
- Recommended to deploy as a **DaemonSet** on all nodes
- Requires host networking to bind to the cluster IP

---

## 📄 License

MIT

---

## 📫 Maintainers

- [Abdellah](https://github.com/abdellahseddikpro)
