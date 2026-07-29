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

<img width="1852" height="471" alt="Screenshot 2026-07-27 203156" src="https://github.com/user-attachments/assets/553e61ee-1401-449f-a445-e4a102316ca8" />
<img width="953" height="90" alt="Screenshot 2026-07-29 212509" src="https://github.com/user-attachments/assets/39fb92ba-58e0-4f78-bfb2-3893d89091e2" />
<img width="1022" height="713" alt="Screenshot 2026-07-29 212632" src="https://github.com/user-attachments/assets/b1edd830-f193-45c6-99a9-8965f88f55ef" />


---

### 2.2 AWS Command Line Interface (v2) Integration
The secondary generation AWS CLI was deployed to facilitate interaction with simulated cloud services locally without needing active AWS subscription credentials or live cloud network routing[cite: 1].

* **Version Inspection:** `aws --version`[cite: 1]

<img width="1032" height="165" alt="Screenshot 2026-07-29 190410" src="https://github.com/user-attachments/assets/413b0709-942b-4914-a149-c1bed5cab640" />
<img width="947" height="97" alt="Screenshot 2026-07-29 190520" src="https://github.com/user-attachments/assets/b1b66c5a-a055-448e-9867-6a9a84280ea9" />

**
---

### 2.3 Kubernetes Control Tools (`kind` & `kubectl`)
The `kind` (Kubernetes-in-Docker) tool and `kubectl` administrative client were deployed to construct and interact with local, container-hosted Kubernetes clusters[cite: 1].

* **kind Tool Version:** `kind --version`[cite: 1]
* **kubectl Client Binary:** `kubectl version --client`[cite: 1]

<img width="306" height="97" alt="Screenshot 2026-07-29 190848" src="https://github.com/user-attachments/assets/020fe327-d28a-46c8-a3de-52c6b3fde5ee" />
<img width="411" height="116" alt="Screenshot 2026-07-29 191304" src="https://github.com/user-attachments/assets/62685032-bb7c-42c5-9180-396d4b7c572c" />

---

### 2.4 Security & Cryptographic Auxiliary Utilities
Confirmed that essential encryption, certificate, and token generation tools are installed and accessible for downstream security assessments[cite: 1]:

* **OpenSSL Binary Check:** `openssl version`[cite: 1]

<img width="757" height="102" alt="Screenshot 2026-07-29 191328" src="https://github.com/user-attachments/assets/73d88dbc-25e1-4f29-93cf-e00e81badde0" />

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
<img width="1877" height="188" alt="Screenshot 2026-07-27 203252" src="https://github.com/user-attachments/assets/08fbb456-6804-411e-9e4a-f2d3c5d18c7f" />
<img width="630" height="212" alt="Screenshot 2026-07-29 195526" src="https://github.com/user-attachments/assets/ac6b3bdf-502a-4d2c-bb18-c7aa064db618" />
<img width="632" height="263" alt="Screenshot 2026-07-29 195624" src="https://github.com/user-attachments/assets/0213392b-19e0-4607-8dd9-29e0f4eb8b09" />

### 3.2 Kubernetes Cluster Deployment (`kind`)
A standalone Kubernetes cluster named ccse was instantiated via Docker and inspected with kubectl[cite: 1].

1. **Cluster Creation:** `kind create cluster --name ccse`
2. **Cluster Info & Node Status:**
   ```bash
   kubectl cluster-info --context kind-ccse
   kubectl get nodes
<img width="1335" height="687" alt="image" src="https://github.com/user-attachments/assets/3021a20c-b289-4ce1-8467-112d00df1487" />




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
