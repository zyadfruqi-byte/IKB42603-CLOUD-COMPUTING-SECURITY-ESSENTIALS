# IKB42603 Cloud Computing Security Essentials
## Lab Report 5: Monitoring, Logging & Incident Detection

**Prepared by:** Ziyad Faruqi Bin Harith Faruqi 

**Course:** IKB42603 Cloud Computing Security Essentials  
**Date:** 9/9/2026  
**Environment:** Kali Linux VM / Docker / kind (Kubernetes)

---

## 1. Executive Summary
This laboratory exercise establishes end-to-end security observability, centralized telemetry, log integrity protection, threat detection, and incident response within cloud infrastructure[cite: 2]. **Session A** focuses on generating application audit logs, shipping logs to an AWS CloudWatch equivalent via LocalStack, and querying centralized telemetry for suspicious login patterns[cite: 2]. **Session B** advances to defensive resilience through cryptographic hash-chaining to make audit trails tamper-evident, multi-event SIEM-style correlation to identify complex attacks, and active containment, evidence preservation, and formal incident documentation[cite: 2].

---

## 2. Technical Prerequisites & Environment
* **Container Infrastructure:** Docker Engine[cite: 2]
* **Cloud Emulation:** LocalStack (AWS CloudWatch Logs service endpoint on port 4566)
* **Client & CLI Tools:** AWS CLI v2, standard POSIX utilities (`grep`, `awk`, `sha256sum`, `sed`, `paste`)

---

## 3. Implementation & Execution Results

### Session A: Logging & Centralisation

#### Task 1: Generate Application Audit Logs
A synthetic application event log (`auth.log`) was created containing both legitimate user logins, a multi-attempt brute-force sequence from an external IP address, and subsequent data exfiltration.

```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT DATA user=admin ip=203.0.113.9 size=500MB
EOF
```
<img width="950" height="463" alt="Screenshot 2026-09-06 212852" src="https://github.com/user-attachments/assets/b5f0f9dc-20c8-4a24-81ad-c1f251294a78" />


#### Task 2: Centralise Logs (Ship to CloudWatch via LocalStack)
LocalStack was initialized to emulate AWS CloudWatch Logs locally on port 4566. A target Log Group (`/ccse/app`) and Log Stream (`auth`) were created. The local audit log entries (`auth.log`) were iteratively transmitted to CloudWatch using the AWS CLI, and then retrieved from the central store to verify log shipping integrity.

```bash
# Iterate through auth.log and ship events with incremental timestamps
TS=$(date +%s000)
while IFS= read -r line; do
  aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" >/dev/null
  TS=$((TS+1000))
done < auth.log

# Verify central collection by reading back stored log events
aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
  --query 'events[].message' --output text
```
<img width="1030" height="173" alt="Screenshot 2026-09-06 212916" src="https://github.com/user-attachments/assets/13725adc-f51c-47d8-b653-9b7f7a745464" />
<img width="1867" height="173" alt="Screenshot 2026-09-06 212935" src="https://github.com/user-attachments/assets/24712f47-5c55-498c-b82b-7b3c1f70c810" />


#### Task 3: Query for Security-Relevant Activity
Targeted shell queries were executed against the log entries to filter security-relevant events[cite: 2]. Specifically, failed login attempts (`LOGIN_FAIL`) were extracted, parsed, sorted, and counted to identify brute-force patterns originating from specific IP addresses.

```bash
# Query for failed login attempts and aggregate count per IP address
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```
<img width="890" height="95" alt="Screenshot 2026-09-06 212958" src="https://github.com/user-attachments/assets/4388a800-f6f3-49aa-ac0a-ec69cbbb247e" />


### Session B: Tamper-Proofing, Detection & Response

#### Task 4: Tamper-Proof (Hash-Chained) Logs
To ensure audit log integrity and non-repudiation, a cryptographic hash chain was constructed using SHA-256. Each log entry's hash was calculated by combining the entry with the preceding record's digest, creating an interdependent chain (`auth.chain`). A tampering attempt was simulated by altering a data exfiltration value in `auth.log` from `500MB` to `5MB` (`auth.tampered`), and integrity verification was executed to demonstrate hash chain breakage.

```bash
PREV=0
while IFS= read -r line; do
 PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
 printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain
cat auth.chain
# Now tamper: change the EXPORT size, re-verify, and watch the chain break
sed 's/500MB/5MB/' auth.log > auth.tampered
PREV=0; BROKE=no
paste -d'|' <(cut -d'|' -f1 auth.chain) <(cut -d'|' -f2 auth.chain) >/dev/null
```
<img width="1742" height="380" alt="Screenshot 2026-09-06 213119" src="https://github.com/user-attachments/assets/b3a4e6d7-d0d2-448c-a55a-7d0049147feb" />
<img width="1018" height="132" alt="Screenshot 2026-09-06 213139" src="https://github.com/user-attachments/assets/1d8e1282-d106-4dd7-bf46-ca0ae1754579" />


#### Task 5: Incident Detection via Event Correlation

SIEM correlation rule logic was implemented to analyze logs across multiple events. By tracking activities associated with a single source IP address (`203.0.113.9`), the system correlated three distinct actions—repeated authentication failures, a successful login, and a subsequent large data exfiltration—triggering a security alert.

```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"
if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
 echo 'ALERT: probable brute-force -> compromise -> data exfiltration';
fi
```

<img width="950" height="302" alt="Screenshot 2026-09-06 213211" src="https://github.com/user-attachments/assets/c59c4ef3-0d8f-4913-abe4-cf9f652e4a03" />


#### Task 6: Incident Response & Evidence Preservation

Active containment was simulated by applying an iptables DROP rule for the malicious IP[cite: 2]. Evidence integrity was secured via timestamped copies and SHA-256 hash digests.

```bash
# CONTAIN: Apply Host Firewall Blocking Rule
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'

# COLLECT: Preserve Forensic Evidence and Generate Integrity Hash
TIMESTAMP=$(date +%Y%m%d)
cp auth.log evidence_${TIMESTAMP}.log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```
<img width="1267" height="161" alt="Screenshot 2026-09-06 213329" src="https://github.com/user-attachments/assets/dec6c41a-c070-410c-9672-f95df439d1f6" />
<img width="1127" height="205" alt="Screenshot 2026-09-06 213341" src="https://github.com/user-attachments/assets/ec19b18c-9590-4c4c-b724-cdc5bf20e7c2" />

---

## 4. Formal Incident Report

### INCIDENT SUMMARY REPORT: INC-2026-0906

* **Detection:** Automated log monitoring identified suspicious activity from source IP `203.0.113.9` triggering security alert `ALERT: probable brute-force -> compromise -> data exfiltration` due to multiple failed authentication attempts followed by successful access.
* **Analysis:** Event correlation confirmed a brute-force account takeover targeting the `admin` user account[cite: 2]. After 4 failed attempts, access was gained at 09:01:22, followed 18 seconds later by an unauthorized bulk data export of 500MB (`EXPORT DATA user=admin ip=203.0.113.9 size=500MB`).
* **Containment:** Active network containment was executed by applying a host-level firewall drop rule (`iptables -A INPUT -s 203.0.113.9 -j DROP`) to block all incoming traffic from the attacker IP address.
* **Evidence & Integrity:** The audit trail was copied to `evidence_20260906.log` and cryptographically sealed by generating a SHA-256 digest (`evidence.sha256`) to ensure chain of custody and forensic data integrity.
* **Lesson Learned:** Implement automated rate-limiting and account lockout policies after 3 failed login attempts, and enforce Multi-Factor Authentication (MFA) on privileged administrative accounts to defeat single-factor credential attacks.

---

## 5. Short-Answer Questions

### Q1. What is the difference between a log and an event? Give an example of each from this lab.
* **Log:** A passive, persistent record of an activity or transaction stored in a file or database. Example: `2025-03-01T09:01:10 LOGIN FAIL user=admin ip=203.0.113.9`.
* **Event:** A real-time actionable signal or notification generated when log entries meet specific security rules or thresholds[cite: 2]. Example: `ALERT: probable brute-force -> compromise -> data exfiltration`.

### Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?
* **Necessity:** Attackers routinely attempt to delete or alter log entries to cover their tracks during a breach.
* **Hash Chain Mechanism:** Each log line's hash includes the hash digest of the preceding entry. If any single record is altered, inserted, or deleted, its hash changes, breaking every subsequent link in the chain and instantly exposing the tampering[cite: 2].

### Q3. How did correlation detect an incident that no single log line revealed?
An isolated `LOGIN FAIL` or individual `EXPORT DATA` request appears routine. SIEM correlation links multiple independent records sharing common attributes (e.g., source IP `203.0.113.9`) across time to reveal the full attack lifecycle: failed login attempts → successful authentication → bulk exfiltration.

### Q4. List the incident-response steps you performed and the goal of each.
1. **Detect:** Correlated audit log telemetry to identify active security incidents.
2. **Contain:** Applied an `iptables` drop rule to block IP `203.0.113.9` and prevent further exfiltration.
3. **Collect:** Created timestamped copies of the log files and generated SHA-256 hashes to preserve forensic evidence integrity.
4. **Document:** Authored a formal incident report detailing detection, impact, containment actions, and lessons learned.

### Q5. How do the same logs serve both security monitoring and compliance evidence?
* **Security Monitoring:** Logs provide real-time operational visibility for threat detection and immediate incident response
* **Compliance Evidence:** Stored, tamper-evident logs serve as historical audit trails required by regulatory frameworks (e.g., SOC 2, PCI-DSS, ISO 27001) to prove that access controls and auditing standards are actively enforced.

---

## 6. Verification Commands & Outputs

<img width="1043" height="405" alt="Screenshot 2026-09-06 213404" src="https://github.com/user-attachments/assets/dc46d3de-9a60-4e92-893c-ed7bcd02a52b" />

---

## 7. Security Best-Practices Checklist

| Security Control | Implementation Status | Lab Verification Evidence |
| :--- | :---: | :--- |
| **Centralized Logging** | Checked | Audit log entries shipped to LocalStack CloudWatch Log Group `/ccse/app` and verified via read-back. |
| **Security Log Querying** | Checked | Filtered failed authentication events (`LOGIN_FAIL`) and aggregated counts per source IP using `grep` and `awk`. |
| **Tamper-Evident Logs** | Checked | Constructed SHA-256 hash chain (`auth.chain`); verified that modifying data (`500MB` to `5MB`) breaks the hash chain. |
| **Event Correlation** | Checked | Correlated repeated login failures, successful login, and data exfiltration from IP `203.0.113.9` to trigger an alert. |
| **Incident Response & Evidence** | Checked | Contained threat via `iptables` drop rule for IP `203.0.113.9`; created timestamped evidence copy with SHA-256 digest. |

