package main

import (
  "flag"
  proxy "kube-api-proxy/internal/kubeApiProxy"
)

func main() { 
   var kubeAPIExternalIP string
   var kubeAPIInternalIP string
   var kubeAPIExternalPort uint
   var kubeAPIInternalport uint
   var syncPeriod int64
   flag.StringVar(&kubeAPIExternalIP, "ext-ip", "127.0.0.1", "External Load Balancer IP for Kubernetes API")
   flag.StringVar(&kubeAPIInternalIP, "int-ip", "127.0.0.1", "Internal IP address of the Kubernetes API server")
   flag.UintVar(&kubeAPIExternalPort, "ext-port", 443, "External Load Balancer port for Kubernetes API")
   flag.UintVar(&kubeAPIInternalport, "int-port", 443, "Internal port number of the Kubernetes API server")
   flag.Int64Var(&syncPeriod, "sync-period", 30, "Time interval in seconds to check and sync nftables rules")
   flag.Parse()
   proxy.Reconcile(kubeAPIExternalIP,kubeAPIInternalIP,kubeAPIExternalPort,kubeAPIInternalport,syncPeriod)
}
