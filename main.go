package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf netmon.c -- -I/usr/include/bpf

type ConnectionEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Proto      uint8
	Pid        uint32
	Netns      uint32
	Comm       [16]byte
	Type       uint8 // 0=connect, 1=accept, 2=close
	CgroupPath [256]byte
}

type ContainerInfo struct {
	ContainerID   string `json:"container_id"`
	PodName       string `json:"pod_name"`
	PodNamespace  string `json:"pod_namespace"`
	ContainerName string `json:"container_name"`
}

type NetworkEvent struct {
	Timestamp     string         `json:"timestamp"`
	Node          string         `json:"node"`
	Type          string         `json:"type"`
	Protocol      string         `json:"protocol"`
	SrcIP         string         `json:"src_ip"`
	SrcPort       uint16         `json:"src_port"`
	DstIP         string         `json:"dst_ip"`
	DstPort       uint16         `json:"dst_port"`
	Pid           uint32         `json:"pid"`
	Process       string         `json:"process"`
	Netns         uint32         `json:"netns"`
	Container     *ContainerInfo `json:"container,omitempty"`
}

type NetworkMonitor struct {
	objs           bpfObjects
	links          []link.Link
	reader         *perf.Reader
	nodeName       string
	containerCache map[string]*ContainerInfo
}

func NewNetworkMonitor() (*NetworkMonitor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown"
	}

	return &NetworkMonitor{
		nodeName:       nodeName,
		links:          make([]link.Link, 0),
		containerCache: make(map[string]*ContainerInfo),
	}, nil
}

func (nm *NetworkMonitor) Load() error {
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading eBPF spec: %w", err)
	}

	if err := spec.LoadAndAssign(&nm.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	return nil
}

func (nm *NetworkMonitor) AttachProbes() error {
	// Attach to tcp_connect
	connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", nm.objs.TraceSysConnect, nil)
	if err != nil {
		return fmt.Errorf("attaching connect tracepoint: %w", err)
	}
	nm.links = append(nm.links, connectLink)

	// Attach to tcp_accept
	acceptLink, err := link.Tracepoint("syscalls", "sys_exit_accept4", nm.objs.TraceSysAccept, nil)
	if err != nil {
		return fmt.Errorf("attaching accept tracepoint: %w", err)
	}
	nm.links = append(nm.links, acceptLink)

	// Attach to tcp_close
	closeLink, err := link.Tracepoint("syscalls", "sys_enter_close", nm.objs.TraceSysClose, nil)
	if err != nil {
		return fmt.Errorf("attaching close tracepoint: %w", err)
	}
	nm.links = append(nm.links, closeLink)

	log.Println("eBPF probes attached successfully")
	return nil
}

func (nm *NetworkMonitor) StartEventReader(ctx context.Context) error {
	var err error
	nm.reader, err = perf.NewReader(nm.objs.Events, os.Getpagesize()*64)
	if err != nil {
		return fmt.Errorf("creating perf reader: %w", err)
	}

	go nm.readEvents(ctx)
	return nil
}

func (nm *NetworkMonitor) readEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := nm.reader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf reader: %v", err)
				continue
			}

			if record.LostSamples > 0 {
				log.Printf("lost %d samples", record.LostSamples)
				continue
			}

			var event ConnectionEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing event: %v", err)
				continue
			}

			nm.handleEvent(&event)
		}
	}
}

func (nm *NetworkMonitor) handleEvent(event *ConnectionEvent) {
	srcIP := intToIP(event.SrcIP)
	dstIP := intToIP(event.DstIP)
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	cgroupPath := string(bytes.TrimRight(event.CgroupPath[:], "\x00"))
	
	eventType := "UNKNOWN"
	switch event.Type {
	case 0:
		eventType = "CONNECT"
	case 1:
		eventType = "ACCEPT"
	case 2:
		eventType = "CLOSE"
	}

	proto := "TCP"
	if event.Proto == 17 {
		proto = "UDP"
	}

	timestamp := time.Now().Format(time.RFC3339)
	
	// Resolve container information
	containerInfo := nm.getContainerInfo(event.Pid, cgroupPath)
	
	netEvent := NetworkEvent{
		Timestamp: timestamp,
		Node:      nm.nodeName,
		Type:      eventType,
		Protocol:  proto,
		SrcIP:     srcIP,
		SrcPort:   event.SrcPort,
		DstIP:     dstIP,
		DstPort:   event.DstPort,
		Pid:       event.Pid,
		Process:   comm,
		Netns:     event.Netns,
		Container: containerInfo,
	}
	
	jsonData, err := json.Marshal(netEvent)
	if err != nil {
		log.Printf("marshaling event: %v", err)
		return
	}
	
	fmt.Println(string(jsonData))
}

func (nm *NetworkMonitor) getContainerInfo(pid uint32, cgroupPath string) *ContainerInfo {
	// Try to get container ID from cgroup path first
	containerID := extractContainerIDFromCgroup(cgroupPath)
	
	// If no container ID from cgroup, try reading from /proc
	if containerID == "" {
		containerID = nm.getContainerIDFromProc(pid)
	}
	
	if containerID == "" {
		return nil
	}
	
	// Check cache
	if info, exists := nm.containerCache[containerID]; exists {
		return info
	}
	
	// Query container runtime for metadata
	info := nm.queryContainerMetadata(containerID)
	if info != nil {
		nm.containerCache[containerID] = info
	}
	
	return info
}

func extractContainerIDFromCgroup(cgroupPath string) string {
	// Docker format: /docker/<container-id>
	// containerd format: /system.slice/docker-<container-id>.scope or /kubepods/.../<container-id>
	// CRI-O format: /kubepods.slice/kubepods-<qos>.slice/.../crio-<container-id>.scope
	
	if strings.Contains(cgroupPath, "docker/") {
		parts := strings.Split(cgroupPath, "docker/")
		if len(parts) > 1 {
			return extractContainerID(parts[1])
		}
	}
	
	if strings.Contains(cgroupPath, "crio-") {
		parts := strings.Split(cgroupPath, "crio-")
		if len(parts) > 1 {
			return extractContainerID(parts[1])
		}
	}
	
	if strings.Contains(cgroupPath, "containerd/") {
		parts := strings.Split(cgroupPath, "containerd/")
		if len(parts) > 1 {
			return extractContainerID(parts[1])
		}
	}
	
	// Generic kubepods format
	if strings.Contains(cgroupPath, "kubepods") {
		parts := strings.Split(cgroupPath, "/")
		for _, part := range parts {
			if len(part) == 64 || (len(part) > 64 && strings.HasSuffix(part, ".scope")) {
				return extractContainerID(part)
			}
		}
	}
	
	return ""
}

func extractContainerID(s string) string {
	// Remove .scope suffix if present
	s = strings.TrimSuffix(s, ".scope")
	
	// Take first 64 characters (full container ID) or 12 (short ID)
	if len(s) >= 64 {
		return s[:64]
	}
	if len(s) >= 12 {
		return s[:12]
	}
	
	return s
}

func (nm *NetworkMonitor) getContainerIDFromProc(pid uint32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	
	// Use host /proc since we're in hostPID mode
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "docker") || strings.Contains(line, "kubepods") || strings.Contains(line, "crio") {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				return extractContainerIDFromCgroup(parts[2])
			}
		}
	}
	
	return ""
}

func (nm *NetworkMonitor) queryContainerMetadata(containerID string) *ContainerInfo {
	// Try containerd first (most common in K8s)
	if info := nm.queryContainerd(containerID); info != nil {
		return info
	}
	
	// Try Docker
	if info := nm.queryDocker(containerID); info != nil {
		return info
	}
	
	// Try CRI-O
	if info := nm.queryCRIO(containerID); info != nil {
		return info
	}
	
	// Return minimal info if runtime query fails
	return &ContainerInfo{
		ContainerID: containerID[:12], // Use short ID
	}
}

func (nm *NetworkMonitor) queryContainerd(containerID string) *ContainerInfo {
	// Try to read from containerd metadata directory
	metadataPath := fmt.Sprintf("/var/lib/containerd/io.containerd.metadata.v1.bolt")
	
	// Fallback to reading pod annotations from filesystem
	// In K8s with containerd, pod info is in /var/lib/containerd/
	pattern := fmt.Sprintf("/var/lib/containerd/*/%s*", containerID)
	matches, _ := filepath.Glob(pattern)
	
	if len(matches) > 0 {
		// Try to extract from config.v2.json or similar
		for _, match := range matches {
			configPath := filepath.Join(match, "config.v2.json")
			if info := nm.parseContainerdConfig(configPath, containerID); info != nil {
				return info
			}
		}
	}
	
	return nil
}

func (nm *NetworkMonitor) parseContainerdConfig(configPath, containerID string) *ContainerInfo {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}
	
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}
	
	info := &ContainerInfo{
		ContainerID: containerID[:12],
	}
	
	// Extract annotations
	if annotations, ok := config["annotations"].(map[string]interface{}); ok {
		if podName, ok := annotations["io.kubernetes.pod.name"].(string); ok {
			info.PodName = podName
		}
		if podNS, ok := annotations["io.kubernetes.pod.namespace"].(string); ok {
			info.PodNamespace = podNS
		}
		if containerName, ok := annotations["io.kubernetes.container.name"].(string); ok {
			info.ContainerName = containerName
		}
	}
	
	return info
}

func (nm *NetworkMonitor) queryDocker(containerID string) *ContainerInfo {
	// Similar approach for Docker
	return nil
}

func (nm *NetworkMonitor) queryCRIO(containerID string) *ContainerInfo {
	// CRI-O stores metadata in /var/lib/containers/storage/
	return nil
}

func (nm *NetworkMonitor) Close() {
	if nm.reader != nil {
		nm.reader.Close()
	}
	
	for _, l := range nm.links {
		l.Close()
	}
	
	nm.objs.Close()
}

func intToIP(ipInt uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, ipInt)
	return ip.String()
}

func main() {
	log.Println("Starting eBPF Network Monitor with Container Resolution")
	
	monitor, err := NewNetworkMonitor()
	if err != nil {
		log.Fatalf("creating monitor: %v", err)
	}
	defer monitor.Close()

	if err := monitor.Load(); err != nil {
		log.Fatalf("loading eBPF programs: %v", err)
	}

	if err := monitor.AttachProbes(); err != nil {
		log.Fatalf("attaching probes: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := monitor.StartEventReader(ctx); err != nil {
		log.Fatalf("starting event reader: %v", err)
	}

	log.Println("Network monitoring active with container resolution. Press Ctrl+C to exit.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	cancel()
	time.Sleep(time.Second)
}