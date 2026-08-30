# IKB42603 Cloud Computing Security Essentials
## Lab Report 4: Access Control & Network Security

**Prepared by:** Ziyad Faruqi Bin Harith Faruqi 
**Course:** IKB42603 Cloud Computing Security Essentials  
**Date:** 30/8/2026  
**Environment:** Kali Linux VM / Docker / kind (Kubernetes)

---

## 1. Executive Summary
This lab focuses on fundamental cloud security controls split across identity and network perimeters. **Session A** demonstrates identity management through HTTP Basic Authentication, Multi-Factor Authentication (MFA) using TOTP, and Role-Based Access Control (RBAC) in Kubernetes using the principle of least privilege. **Session B** implements network security controls, including three-tier container network segmentation, default-deny host firewall rules with `iptables`, and container hardening using non-root execution, read-only filesystems, capability drops, and image vulnerability scanning.

---

## 2. Environment Setup & Prerequisites
* **Operating System:** Linux / macOS / WSL2
* **Container Runtime:** Docker Engine
* **Kubernetes Environment:** `kind` (Kubernetes in Docker) & `kubectl`
* **Tools Used:** `htpasswd`, `oathtool`, `curl`, `iptables`, `trivy`

---

## 3. Implementation & Results

### Session A: Identity & Access Control

#### Task 1: Authentication (Password-Protected Service)
An Nginx container was configured with HTTP Basic Authentication using an encrypted `.htpasswd` file containing user credentials (`student:P@ssword!`).

```bash
# Generate htpasswd file
docker run --rm httpd:alpine htpasswd -nbB student 'P@ssword!' > htpasswd.txt

# Configure Nginx with auth_basic
cat > default.conf <<'EOF'
server {
    listen 80;
    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
        return 200 'Authenticated OK\n';
    }
}
EOF

# Run Nginx container
docker run --rm -d --name authsvc -p 8080:80 \
  -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
  -v $(pwd)/htpasswd.txt:/etc/nginx/.htpasswd nginx

  curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080 # 401
  curl -s -u student:'P@ssw0rd!' http://localhost:8080 # 200 
```
<img width="1072" height="331" alt="Screenshot 2026-08-30 201120" src="https://github.com/user-attachments/assets/938a62a8-4404-49fa-947a-17d392eb87c0" />
<img width="997" height="210" alt="Screenshot 2026-08-30 201410" src="https://github.com/user-attachments/assets/a7ed6e5f-5243-4dc2-9710-e39f9571aaf4" />




#### Task 2: Second Factor Authentication (MFA / TOTP)
A 20-byte base32 shared secret was generated to simulate Time-Based One-Time Password (TOTP) enrolment. Dynamic passcodes were validated using oathtool.

```bash
# Generate secret and print current TOTP code
SECRET=$(head -c20 /dev/urandom | base32)
echo "Enrol secret: $SECRET"
oathtool --totp -b "$SECRET"

# Validate input code
read -p 'Enter 6-digit code: ' CODE
[ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

<img width="961" height="173" alt="Screenshot 2026-08-30 201551" src="https://github.com/user-attachments/assets/2ee03dbc-a147-46fd-98a1-b45f595ecafd" />
<img width="1101" height="163" alt="Screenshot 2026-08-30 201620" src="https://github.com/user-attachments/assets/5076cd44-1127-417b-af69-7840499657d1" />




#### Task 3: Authorization (Kubernetes RBAC Roles)
A Kubernetes cluster was provisioned via `kind`. A ServiceAccount (`dev`) was created in namespace `app` with a Role permitting only `get` and `list` operations on pods.

```bash
# Cluster & namespace setup
kind create cluster --name ccse-lab4
kubectl create namespace app
kubectl create serviceaccount dev -n app

# Define Role and Binding
kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev
```

<img width="632" height="406" alt="Screenshot 2026-08-30 202244" src="https://github.com/user-attachments/assets/ddec6d6c-57af-48ad-8449-81adbf23de9c" />
<img width="1045" height="292" alt="Screenshot 2026-08-30 202310" src="https://github.com/user-attachments/assets/1ff99049-499f-4919-98ec-4ec3e2317dac" />


**Permission Verification (`kubectl auth can-i`):**
```bash
SA="system:serviceaccount:app:dev"

kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```
<img width="642" height="380" alt="Screenshot 2026-08-30 202325" src="https://github.com/user-attachments/assets/663b1192-1fa1-411b-bdeb-07ce5a18eaf4" />


### Session B: Network Security & Host Hardening

#### Task 4: Network Segmentation (Three-Tier Architecture)
Isolated Docker bridge networks (`frontend-net` and `backend-net`) were created to enforce architectural separation[cite: 1]. The `db` service was placed on `backend-net`, `web` on `frontend-net`, and `app` attached to both networks to act as an intermediary bridge[cite: 1].

```bash
# Network creation
docker network create frontend-net
docker network create backend-net

# Service deployment using Alpine-based Nginx for netcat/curl availability
docker run -d --name db --network backend-net redis:alpine
docker run -d --name app --network backend-net nginx:alpine
docker network connect frontend-net app
docker run -d --name web --network frontend-net nginx:alpine
```
<img width="831" height="151" alt="Screenshot 2026-08-30 202358" src="https://github.com/user-attachments/assets/715a3c54-5d65-437b-b0c8-342ccae0101a" />
<img width="1018" height="627" alt="Screenshot 2026-08-30 202856" src="https://github.com/user-attachments/assets/03f02e8b-1f8f-410b-adbb-c30acebee12b" />


**Connectivity Verification:**
* **`web` -> `db` direct access test (Should fail):**
  ```bash
  docker exec web sh -c 'apk add -q netcat-openbsd; nc -z -w 3 db 6379 || echo BLOCKED'
  ```
<img width="1212" height="170" alt="Screenshot 2026-08-30 203218" src="https://github.com/user-attachments/assets/be2eb550-f3eb-4a74-b4e8-fcc014040281" />


* **`app` -> `db` backend access test (Should succeed):**
  ```bash
  docker exec app sh -c 'apk add -q netcat-openbsd; nc -z -w 3 db 6379 && echo REACHABLE'
  ```
<img width="1872" height="407" alt="Screenshot 2026-08-30 203154" src="https://github.com/user-attachments/assets/45182563-55d4-4e81-a75c-a016ebfd2b93" />


#### Task 5: Firewall Rules (Default-Deny Model)
A host-level default-deny firewall configuration was demonstrated inside an isolated Alpine container using `iptables` with `NET_ADMIN` capabilities. The default `INPUT` chain policy was set to `DROP`, blocking all traffic except for explicit allowed rules on HTTPS port 443 and the loopback interface (`lo`).

```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '
apk add -q iptables; \
iptables -P INPUT DROP; \
iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
iptables -A INPUT -i lo -j ACCEPT; \
iptables -L INPUT -n'
```
<img width="1008" height="421" alt="Screenshot 2026-08-30 203306" src="https://github.com/user-attachments/assets/c5dec428-ede7-4595-802b-d243ecfca5a5" />


#### Task 6: Container Hardening & Vulnerability Scanning
An unprivileged Nginx container (`nginxinc/nginx-unprivileged`) was executed using defensive security configurations: non-root execution (`--user 1000:1000`), a read-only root filesystem (`--read-only`), dropping all Linux kernel capabilities (`--cap-drop ALL`), preventing privilege escalation (`--security-opt no-new-privileges`), and mounting a writable temporary filesystem at `/tmp` (`--tmpfs /tmp`). Additionally, the image was scanned for vulnerabilities using Trivy.

```bash
# Run hardened container instance
docker run -d --name hardened \
  --user 1000:1000 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp \
  nginxinc/nginx-unprivileged

# Inspect runtime configuration parameters
docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'

# Scan container image for HIGH and CRITICAL vulnerabilities
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

<img width="1043" height="548" alt="Screenshot 2026-08-30 203507" src="https://github.com/user-attachments/assets/295520e4-ce01-4af8-93e0-0f836bd45e41" />
<img width="1142" height="60" alt="Screenshot 2026-08-30 203721" src="https://github.com/user-attachments/assets/3586ae14-50e3-41cb-a5dd-04d263ff950d" />
<img width="1851" height="498" alt="Screenshot 2026-08-30 203734" src="https://github.com/user-attachments/assets/b64583bc-c4c8-4670-b59b-e0e8f6c88c09" />


---

## 4. Deliverables & Short-Answer Questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.
* **Authentication (AuthN):** Verifies identity ("who you claim to be"). In Task 1, HTTP Basic Authentication verified supplied credentials (`student:P@ssword!`) against the stored `.htpasswd` hash before granting access.
* **Authorization (AuthZ):** Defines privilege levels ("what you are allowed to do"). In Task 3, after identity assertion, Kubernetes RBAC evaluated permissions, allowing the developer ServiceAccount to list pods (`yes`) while blocking deployment creation and pod deletion (`no`).

### Q2. Why is MFA so effective, and which attacks does it defeat?
* **Effectiveness:** Multi-Factor Authentication requires verification across distinct authentication factor classes (something you know + something you have).
* **Attacks Defeated:** Neutralizes credential stuffing, password spraying, keylogging, and brute-force attacks, as compromised static passwords remain insufficient without access to the dynamic TOTP generator.

### Q3. How does network segmentation limit the damage of a compromised web server?
Network segmentation restricts communication channels between application layers. If an attacker compromises the web container on `frontend-net`, the lack of direct network interface routing blocks lateral movement to database services residing on `backend-net`.

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?
* **Default-Deny Principle:** Drops all inbound traffic by default (`INPUT DROP`), ensuring network exposure is limited strictly to explicitly configured whitelist rules (e.g., port 443).
* **Cloud Security Groups Connection:** Cloud Security Groups employ the same zero-trust model, blocking incoming connections automatically until explicit inbound traffic rules are defined.

### Q5. List the hardening measures you applied and the attack surface each one removes.[cite: 1]
1. **Non-Root Execution (`--user 1000:1000`):** Prevents container breakouts from acquiring root-level privileges on the underlying host operating system.
2. **Read-Only Root Filesystem (`--read-only`):** Prevents dynamic file modifications, execution of downloaded malicious binaries, configuration tampering, and persistence mechanism deployment.
3. **Capability Drop (`--cap-drop ALL`):** Strips default Linux kernel capabilities, preventing privilege escalation exploits within the container process.

---

## 5. Security Best-Practices Checklist

| Security Control | Implementation Status | Lab Verification Evidence |
| :--- | :---: | :--- |
| **Service Authentication** | Checked | Unauthenticated HTTP requests rejected with `401 Unauthorized`; valid credentials return `200 OK` (Task 1). |
| **Multi-Factor Authentication (MFA)** | Checked | TOTP dynamic shared secret enrolled and validated using `oathtool` (Task 2). |
| **RBAC Authorization** | Checked | Kubernetes developer ServiceAccount permitted to list pods but restricted from deployment creation and pod deletion (Task 3). |
| **Network Segmentation** | Checked | Web container isolated on `frontend-net`, preventing direct network access to `db` on `backend-net` (Task 4). |
| **Default-Deny Firewall** | Checked | `iptables` ruleset configured to `DROP` incoming traffic by default, explicitly permitting port 443 and loopback (Task 5). |
| **Container Hardening & Scanning** | Checked | Container deployed with non-root UID `1000:1000`, `--read-only` root filesystem, `--cap-drop ALL`, and scanned via Trivy (Task 6). |

---

## 6. Verification Commands & Outputs

<img width="811" height="590" alt="Screenshot 2026-08-30 203751" src="https://github.com/user-attachments/assets/4196f90b-7d37-4936-b1fc-05bbdee28285" />


---

## 7. Conclusion

This laboratory exercise successfully demonstrated the dual-layer approach to cloud infrastructure defense: securing **who** gets in (Access Control) and limiting **what** can be accessed or exploited (Network Security & Hardening). 

By enforcing authentication via HTTP Basic Auth and TOTP-based Multi-Factor Authentication[cite: 1], static credential compromise risks were significantly mitigated. Role-Based Access Control (RBAC) in Kubernetes validated the principle of least privilege by scope-limiting operational permissions. On the network side, container network segmentation demonstrated how isolating application tiers prevents lateral movement in multi-container setups[cite: 1], mirroring the cloud security group logic executed through host-level `iptables` default-deny policies. Finally, runtime container hardening flags (`--user`, `--read-only`, `--cap-drop ALL`) coupled with static vulnerability scanning through Trivy ensured a defense-in-depth posture capable of containing container escape and privilege escalation vectors.
