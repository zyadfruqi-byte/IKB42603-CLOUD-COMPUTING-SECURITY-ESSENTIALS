# Lab 2 Report: Secure Isolation & Multi-Tenancy

**Prepared by:** Ziyad Faruqi Bin Harith Faruqi 
**Course:** IKB42603 Cloud Computing Security Essentials  
**Date:** 12/8/2026  
**Environment:** Kali Linux VM / Docker / kind (Kubernetes)  

---

## 1. Executive Summary

This lab demonstrated compute, network, and storage multi-tenancy isolation strategies within a shared Kubernetes and container environment. In Session A, tenant workloads were deployed into isolated namespaces with resource quotas to mitigate noisy-neighbor risks, highlighting the critical security hazard of Kubernetes' default-open network model. In Session B, defense-in-depth controls were enforced: a default-deny NetworkPolicy blocked unauthorized cross-tenant communication, RBAC rules strictly compartmentalized storage secrets, and zeroization shredding demonstrated data remanence mitigation.

---

## 2. Environment Setup: Cluster Creation & Calico CNI Installation

A Kubernetes cluster named `ccse-lab2` was created using `kind` with the default CNI disabled to allow Calico to enforce network policies.

```bash
# 1. Create cluster with default CNI disabled
cat <<EOF # ### & --config="-" --name --timeout="180s" -f -n 192.168.0.0/16 2. 3. CNI Calico Cluster Deliverable: EOF Initialization Install Screenshot Status Verify ``` apiVersion: apply ccse-lab2 cluster create daemonset/calico-node disableDefaultCNI: https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml kind kind.x-k8s.io/v1alpha4 kind: kube-system kubectl networking: plugin podSubnet: readiness rollout status true | 
> 
> 

---

## 3. Session A: Compute Isolation & Default-Open Risk

### Task 1: Two Tenants on One Cluster
Two customer tenants (`tenant-a` and `tenant-b`) were provisioned as logical namespaces sharing the cluster infrastructure.

```bash
# Create namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# Deploy web workloads
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx

# Expose services
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80

# Verify workloads
kubectl get pods,svc -n tenant-a
kubectl get pods,svc -n tenant-b