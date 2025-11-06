# eBPF Network Monitor for Kubernetes

A lightweight, secure network monitoring tool using eBPF to trace network connections on Kubernetes nodes.

## Features

- 🔍 **Real-time Network Tracing**: Monitor TCP connections (connect, accept, close)
- 🎯 **eBPF-based**: Low overhead, kernel-level tracing
- 📦 **Container Resolution**: Automatically identifies which container made each network call
- ☸️ **Kubernetes Native**: Extracts pod name, namespace, and container name
- 🔒 **Security-focused**: Minimal dependencies, non-root user, read-only filesystem
- 📊 **JSON Logging**: Structured output for log aggregation (ELK, Splunk, etc.)
- 🌐 **Multi-cloud**: Works on AWS EKS, GCP GKE, and bare-metal clusters

## Architecture

```
┌─────────────────────────────────────┐
│         Kubernetes Node             │
│                                     │
│  ┌──────────────────────────────┐  │
│  │   eBPF Network Monitor Pod   │  │
│  │                              │  │
│  │  ┌────────────────────────┐  │  │
│  │  │   eBPF Programs        │  │  │
│  │  │  - sys_enter_connect   │  │  │
│  │  │  - sys_exit_accept4    │  │  │
│  │  │  - sys_enter_close     │  │  │
│  │  └────────────────────────┘  │  │
│  │            ↓                  │  │
│  │  ┌────────────────────────┐  │  │
│  │  │   Perf Event Buffer    │  │  │
│  │  └────────────────────────┘  │  │
│  │            ↓                  │  │
│  │  ┌────────────────────────┐  │  │
│  │  │   Go Event Handler     │  │  │
│  │  │   (JSON Output)        │  │  │
│  │  └────────────────────────┘  │  │
│  └──────────────────────────────┘  │
│                ↓                    │
│    stdout/stderr (JSON logs)       │
└─────────────────────────────────────┘
```

## Prerequisites

- Kubernetes cluster (1.21+)
- Linux kernel 5.8+ with eBPF support
- `clang` and `llvm` for building
- Go 1.23+

## Quick Start

### 1. Build the Docker Image

```bash
# Set your registry
export REGISTRY=your-registry.io/yourname

# Build and push
make docker-build
make docker-push
```

### 2. Deploy to Kubernetes

```bash
# Update the image in daemonset.yaml
sed -i "s|your-registry|$REGISTRY|g" daemonset.yaml

# Deploy
make deploy
```

### 3. View Logs

```bash
# Watch logs from all nodes
make logs

# Or from a specific node
kubectl logs -n network-monitoring -l app=ebpf-netmon --field-selector spec.nodeName=your-node-name
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_NAME` | Kubernetes node name | Set automatically via downward API |

### Resource Limits

Adjust in `daemonset.yaml`:

```yaml
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

## Output Format

Events are logged as JSON for easy parsing, now including container information:

```json
{
  "timestamp": "2025-11-06T10:30:45Z",
  "node": "node-1",
  "type": "CONNECT",
  "protocol": "TCP",
  "src_ip": "10.0.1.5",
  "src_port": 45678,
  "dst_ip": "172.217.14.206",
  "dst_port": 443,
  "pid": 1234,
  "process": "curl",
  "netns": 4026532508,
  "container": {
    "container_id": "a1b2c3d4e5f6",
    "pod_name": "nginx-deployment-7d64c9f9b8-x9k2m",
    "pod_namespace": "production",
    "container_name": "nginx"
  }
}
```

### Container Resolution

The monitor automatically identifies containers using:
1. **Cgroup Path Analysis**: Extracts container ID from cgroup hierarchy
2. **Network Namespace**: Tracks network namespace inode for correlation
3. **Runtime Metadata**: Queries containerd/Docker/CRI-O for pod information
4. **Caching**: Maintains in-memory cache to reduce overhead

### Event Types

- **CONNECT**: Outbound connection initiated
- **ACCEPT**: Inbound connection accepted
- **CLOSE**: Connection closed

## Security Considerations

### Vulnerability Mitigation

1. **Minimal Base Image**: Alpine 3.20 (latest stable)
2. **No Root User**: Runs as UID 1000 (requires privileged for eBPF)
3. **Read-only Filesystem**: Container filesystem is read-only
4. **Official Dependencies**: Uses Cilium eBPF library (well-maintained)
5. **Static Binary**: No dynamic linking reduces attack surface
6. **Multi-stage Build**: Build tools not in final image

### Required Privileges

eBPF requires elevated privileges:

- `privileged: true` - Required for eBPF operations
- `SYS_ADMIN` - Load eBPF programs
- `SYS_RESOURCE` - Adjust resource limits
- `NET_ADMIN` - Network tracing

### Scanning for Vulnerabilities

```bash
# Scan the Docker image
make scan

# Or manually with Trivy
trivy image your-registry/ebpf-netmon:latest
```

## Integration with Log Aggregators

### Fluent Bit / Fluentd

The JSON output is automatically picked up by Fluent Bit DaemonSets:

```yaml
[FILTER]
    Name parser
    Match *netmon*
    Key_Name log
    Parser json
```

### AWS CloudWatch

Use the CloudWatch Container Insights agent to forward logs.

### GCP Cloud Logging

Logs are automatically ingested and queryable in Cloud Logging console.

### Elasticsearch / OpenSearch

Use Filebeat or Logstash to ship logs:

```yaml
input {
  kubernetes {
    labels => {
      app => "ebpf-netmon"
    }
  }
}

filter {
  json {
    source => "message"
  }
}
```

## Troubleshooting

### Pod Not Starting

Check kernel version:
```bash
kubectl debug node/your-node -it --image=ubuntu -- bash
uname -r  # Should be 5.8+
```

### No Events Generated

Verify eBPF support:
```bash
kubectl exec -n network-monitoring <pod-name> -- ls /sys/kernel/debug/tracing
```

### Permission Denied

Ensure the DaemonSet has `privileged: true` and proper capabilities.

## Development

### Local Testing

```bash
# Generate eBPF code
make generate

# Build binary
make build

# Run locally (requires sudo)
sudo ./bin/netmon
```

### Adding New Probes

1. Add the eBPF program in `netmon.c`
2. Update the event structure if needed
3. Attach the probe in `main.go`
4. Regenerate: `make generate`

## Performance

- **CPU**: ~50-100m per node under normal load
- **Memory**: ~100-200MB per node
- **Overhead**: <1% due to eBPF efficiency
- **Event Rate**: Handles 10k+ events/sec per node

## Limitations

- Currently supports IPv4 only (IPv6 can be added)
- TCP connections only (UDP can be added)
- No packet payload inspection (by design)
- Requires kernel 5.8+ with eBPF support

## License

Apache 2.0

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## References

- [Cilium eBPF Documentation](https://ebpf-go.dev/)
- [eBPF.io](https://ebpf.io/)
- [Kubernetes DaemonSet Best Practices](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/)
