# Lab 0 Documentation: Setup & Verification of Cloud Security Environment

**Submitted by:** Ziyad Faruqi Bin Harith Faruqi

**Module:** IKB42603 Cloud Computing Security Essentials  
**Execution Date:** 29/7/2026

**Operating Environment:** Kali Linux Workstation (VirtualBox Platform)  

---

## 1. Overview & Objective
This report details the deployment, configuration, and structural validation of the local security testing infrastructure designated for the IKB42603 laboratory modules. Core utilities—including Docker Desktop/Engine, AWS CLI v2, kind, and kubectl—were installed, integrated, and verified to run entirely offline on local hardware.

---

## 2. Infrastructure Installation & Technical Validation

### 2.1 Container Engine Setup & Storage Provisioning
Docker provides the underlying container runtime necessary to deploy microservices and cloud simulation endpoints locally. Virtual machine disk space was expanded prior to initialization to ensure adequate room for container layers and Kubernetes control-plane images.

* **Version Inspection:** `docker --version`
* **Runtime Verification Test:** `docker run --rm hello-world`[cite: 1]

> **<img width="1544" height="800" alt="image" src="https://github.com/user-attachments/assets/f68da26a-7b4f-4fc4-8d05-5b0506f91de1" /

**

---

### 2.2 AWS Command Line Interface (v2) Integration
The secondary generation AWS CLI was deployed to facilitate interaction with simulated cloud services locally without needing active AWS subscription credentials or live cloud network routing[cite: 1].

* **Version Inspection:** `aws --version`[cite: 1]

> **<img width="1286" height="134" alt="image" src="https://github.com/user-attachments/assets/49c5a1f8-193c-45e9-97e2-a63c510b0195" />
**
---

### 2.3 Kubernetes Control Tools (`kind` & `kubectl`)
The `kind` (Kubernetes-in-Docker) tool and `kubectl` administrative client were deployed to construct and interact with local, container-hosted Kubernetes clusters[cite: 1].

* **kind Tool Version:** `kind --version`[cite: 1]
* **kubectl Client Binary:** `kubectl version --client`[cite: 1]

> **<img width="630" height="302" alt="image" src="https://github.com/user-attachments/assets/c108f944-f11b-43c5-9332-6765f92fd30e" />
**
---

### 2.4 Security & Cryptographic Auxiliary Utilities
Confirmed that essential encryption, certificate, and token generation tools are installed and accessible for downstream security assessments[cite: 1]:

* **OpenSSL Binary Check:** `openssl version`[cite: 1]

> **<img width="1042" height="124" alt="image" src="https://github.com/user-attachments/assets/f22c807e-7d73-400e-a195-2aa73a3405ba" />
**
---

## 3. Environment Integration & Service Testing

### 3.1 LocalStack Emulation & Local AWS Verification
LocalStack was instantiated inside a Docker container to simulate core AWS API endpoints locally on port `4566`[cite: 1].

1. **Verify Container Execution:** `docker ps`
2. **Ping Service Endpoint:** `curl http://localhost:4566/_localstack/health`[cite: 1]
3. **AWS CLI Mock Authentication & API Request:**
   ```bash
   aws configure set aws_access_key_id test
   aws configure set aws_secret_access_key test
   aws configure set region us-east-1
   EP='--endpoint-url=http://localhost:4566'
   aws $EP sts get-caller-identity
<img width="846" height="286" alt="image" src="https://github.com/user-attachments/assets/5bbb8f8c-47db-42e0-a4a4-b57f08e7bd99" />

### 3.2 Kubernetes Cluster Deployment (`kind`)
A standalone Kubernetes cluster named ccse was instantiated via Docker and inspected with kubectl[cite: 1].

1. **Cluster Creation:** `kind create cluster --name ccse`
2. **Cluster Info & Node Status:**
   ```bash
   kubectl cluster-info --context kind-ccse
   kubectl get nodes
<img width="1762" height="1088" alt="image" src="https://github.com/user-attachments/assets/5d27a676-1620-4087-9e5e-8942489a6fd5" />

## 4. Verification Checklist Summary

| Verification Task | Command / Check | Status |
| :--- | :--- | :---: |
| Docker Engine Active | `docker run --rm hello-world` | ✅ Pass |
| AWS CLI v2 Installed | `aws --version` | ✅ Pass |
| Kubernetes CLI Ready | `kubectl version --client` | ✅ Pass |
| LocalStack Health | `curl http://localhost:4566/_localstack/health` | ✅ Pass |
| LocalStack STS Identity | `aws $EP sts get-caller-identity` | ✅ Pass |
| Kubernetes Cluster Ready | `kubectl get nodes` | ✅ Pass |

## 5. Conclusion

The local cloud security testing environment has been fully provisioned, integrated, and validated[cite: 1]. All container management frameworks, local cloud mock services, and orchestrators are confirmed operational and ready for subsequent laboratory assignments[cite: 1].