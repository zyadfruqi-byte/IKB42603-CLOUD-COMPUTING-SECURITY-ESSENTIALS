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

# 1. Create cluster with default CNI disabled

```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
 disableDefaultCNI: true
 podSubnet: 192.168.0.0/16
EOF
kubectl apply -f
https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```
<img width="1415" height="752" alt="Screenshot 2026-08-12 125213" src="https://github.com/user-attachments/assets/24af0070-8d6d-44bc-9dde-eadbf45ad916" />
<img width="1136" height="122" alt="Screenshot 2026-08-12 125154" src="https://github.com/user-attachments/assets/7a366034-2a0f-4d2f-892b-6ec7b2c0211e" />

---

## 3. Session A: Compute Isolation & Default-Open Risk

### Task 1: Two Tenants on One Cluster
Two customer tenants (`tenant-a` and `tenant-b`) were provisioned as logical namespaces sharing the cluster infrastructure.

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
```
<img width="507" height="147" alt="Screenshot 2026-08-12 125232" src="https://github.com/user-attachments/assets/67e92a16-a1b6-4c44-9920-842552a4b0a9" />
<img width="876" height="397" alt="Screenshot 2026-08-12 125258" src="https://github.com/user-attachments/assets/3ceef1a9-aa9f-4e18-855c-2fc7d82265c5" />

---

## Task 2: Observe the Default-Open Risk

By default, pods in one namespace can reach services running in another namespace. To demonstrate this default-open behavior, the Cluster IP of `tenant-b`'s web service was retrieved, and an HTTP probe was initiated from `tenant-a`.

1. **Retrieve Tenant B Web Service IP:**
   ```bash
   kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
   ```
<img width="928" height="95" alt="Screenshot 2026-08-12 125550" src="https://github.com/user-attachments/assets/95ae07e0-b532-4752-a52e-4e6eba47bf3b" />

---

## Task 2: Execute Cross-Namespace Probe from Tenant A:
```bash
ectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
 -- curl -s -m 5 http://<B_IP> -o /dev/null -w 'HTTP %{http_code}\n'
```
<img width="1062" height="147" alt="Screenshot 2026-08-12 125941" src="https://github.com/user-attachments/assets/00c3890c-57ae-4798-bba6-98d4697bc418" />

---

## Task 3: Contain the Noisy Neighbour (Resource Quotas)

Multi-tenancy isolation requires restricting resource consumption so one tenant cannot exhaust shared node capacity and impact other workloads[cite: 1]. A `ResourceQuota` was applied to `tenant-a` to cap maximum CPU, memory, and pod allocations[cite: 1].

1. **Apply Resource Quota to Tenant A:**
   ```bash
   cat <<EOF | kubectl apply -f -
   apiVersion: v1
   kind: ResourceQuota
   metadata:
    name: tenant-a-quota
    namespace: tenant-a
   spec:
    hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
   EOF

   kubectl describe resourcequota tenant-a-quota -n tenant-a

<img width="811" height="526" alt="Screenshot 2026-08-12 130123" src="https://github.com/user-attachments/assets/4a9a9b9b-8f99-45d0-810e-a42d867a5bb0" />

---

## 4. Session B: Network & Storage Isolation

Session B transitions from observing multi-tenancy vulnerabilities to enforcing active security controls. This section implements network segmentation via default-deny policies, secret isolation using Role-Based Access Control (RBAC), and storage sanitization to prevent data remanence.

---

## Task 4: Default-Deny Network Isolation

A default-deny ingress NetworkPolicy was enacted in tenant-b to enforce network segmentation.
```bash
# Apply default-deny ingress policy in tenant-b
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes:
  - Ingress
EOF

# Re-run the probe from tenant-a to tenant-b
B_IP=$(kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}')
kubectl -n tenant-a run probe-rm-it --image=curlimages/curl --restart=Never -- \
  curl -s -m 5 http://$B_IP -o /dev/null -w 'HTTP %{http_code}\n'
```

<img width="812" height="382" alt="image" src="https://github.com/user-attachments/assets/b184d3a4-ef78-4944-99c7-e982e51555a5" />
<img width="1866" height="125" alt="Screenshot 2026-08-12 130317" src="https://github.com/user-attachments/assets/ae069103-ac2f-400c-a377-4e796b4605e9" />

---

## Task 6: Data Remanence & Secure Deletion

Data persistence following standard file unlinking was contrasted against cryptographic zeroization (shredding) inside container volumes.
```bash
# Create a file, delete it normally, then show the bytes may persist
docker run --rm -v ccse-vol:/data alpine sh -c \
 'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
 grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
# Secure wipe: overwrite before delete (shred)
docker run --rm -v ccse-vol:/data alpine sh -c \
 'echo SENSITIVE > /data/phi2.txt; sync; \
 dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt;
echo wiped'
```

<img width="986" height="272" alt="Screenshot 2026-08-12 130757" src="https://github.com/user-attachments/assets/5671c171-c2d0-436e-9c87-df5b0edaeccd" />
<img width="1045" height="227" alt="Screenshot 2026-08-12 130820" src="https://github.com/user-attachments/assets/3525ac57-6b5e-4c4e-9408-41f73068163e" />

---

## 5. Verification Commands Deliverable

Executing required verification commands across active network policies and resource quota limits:
```bash
# 1. Audit all active NetworkPolicies across namespaces
kubectl get networkpolicy -A

# 2. Inspect active resource quota specs in tenant-a
kubectl describe resourcequota tenant-a-quota -n tenant-a
```
<img width="737" height="317" alt="Screenshot 2026-08-12 142652" src="https://github.com/user-attachments/assets/c45e3583-ecfd-4258-96c6-136df4dee822" />

 ---

 ## 6. Short-Answer Questions

### Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?
**Answer:** By default, Kubernetes leaves all network doors wide open so every container can easily talk to any other container. In a shared cloud where different companies or teams host their apps together, this is dangerous because if an attacker hacks into one container, they can freely look around and attack other tenants' private apps and data.

### Q2. Explain the default-deny principle and how your Network Policy implements it.
**Answer:** The "default-deny" principle means "lock all doors first, and only open them for trusted guests." The Network Policy implements this by blocking all incoming traffic to `tenant-b` by default, so outside requests (like the probe from `tenant-a`) are immediately dropped unless explicitly allowed.

### Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?
**Answer:** Virtual Machines (VMs) are like completely separate houses with their own infrastructure, while containers are like rooms inside the same apartment sharing one main system (the Linux kernel). Because sharing a system makes containers easier to escape if hacked, you should put your workloads inside a separate VM when running untrusted code or handling super sensitive data.

### Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?
**Answer:** Data remanence means leftover data that stays on a hard drive even after you click "delete". In the cloud, you don't own the physical hard drives to destroy them, so cryptographic erasure is used: you encrypt the data with a key, and when you want to delete the data forever, you simply throw away the key, making the leftover data completely unreadable.

### Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?
**Answer:**
* **Task 1 & Task 3 (Compute Isolation):** Used Namespaces to separate apps and ResourceQuotas to limit CPU and memory so one tenant can't hog all the system power.
* **Task 2 & Task 4 (Network Isolation):** Tested how containers talk to each other over the network and used NetworkPolicies to block unwanted connections.
* **Task 5 & Task 6 (Storage Isolation):** Used RBAC rules to stop one tenant from viewing another tenant's secret files and tested how to safely wipe deleted data from disk volumes.

---

## 7. Deliverables & Checklists Summary

| Session | Task / Verification Objective | Command / Test Executed | Expected Result / Status |
| :--- | :--- | :--- | :---: |
| **Session A** | Workload Setup | `kubectl get pods,svc -n tenant-a` | ✅ Pass |
| **Session A** | Default-Open Risk Observation | `curl http://<B_IP>` from `tenant-a` | ✅ Pass (HTTP 200) |
| **Session A** | Compute Isolation (Resource Quota) | `kubectl describe resourcequota tenant-a-quota -n tenant-a` | ✅ Pass |
| **Session B** | Network Isolation Policy | `curl http://<B_IP>` post-NetworkPolicy | ✅ Pass (Timeout) |
| **Session B** | Storage & Secret Isolation | `kubectl auth can-i get secrets -n tenant-b --as=$SA` | ✅ Pass (NO) |
| **Session B** | Data Remanence & Zeroization | Volume shred ding with `dd if=/dev/zero` | ✅ Pass |

---

### Security Best-Practices Checklist

* [x] **Compute Isolation:** Tenants are separated into distinct Kubernetes namespaces (`tenant-a` and `tenant-b`).
* [x] **Resource Protection:** Resource quotas are configured to prevent a noisy neighbour from exhausting shared CPU/memory capacity.
* [x] **Network Isolation:** A default-deny Network Policy blocks unauthorized cross-tenant network traffic (verified with before/after probes).
* [x] **Storage Protection:** Per-tenant secrets are isolated and completely unreadable by unauthorized tenant service accounts via RBAC.
* [x] **Data Hygiene:** Remanence risks are understood and secure deletion via zeroization (shredding) was demonstrated.

---
### 8. Conclusion

Lab 2 showed the benefit of applying defense-in-depth for multi-tenant cloud environments. Namespaces are an example of compute-level security that can group workloads while preventing processes from affecting unrelated ones, but do not provide network separation or resource containment of your workloads. By utilizing default deny NetworkPolicies along with RBAC policies and Resource Quotas, strong multitenancy controls can be established across compute, networking, and persistent storage.
