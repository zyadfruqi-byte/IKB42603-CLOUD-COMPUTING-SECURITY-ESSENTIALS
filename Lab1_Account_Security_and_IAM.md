# Lab 1 Report: Cloud Account Security, Identity & Access Management

**Prepared by:** Ziyad Faruqi Bin Harith Faruqi

**Course:** IKB42603 Cloud Computing Security Essentials  
**Date:** 29/7/2026

**Environment:** Kali Linux VM (VirtualBox)  

---

## 1. Executive Summary
This report documents the implementation and verification of cloud identity governance and platform-enforced Role-Based Access Control (RBAC) across two distinct operational phases. In Session A, LocalStack was deployed to emulate AWS IAM services locally, replacing unrestricted root usage with group-managed administrator access, enforcing least-privilege read-only permissions for an analyst identity to limit blast radius, and practicing credential lifecycle hygiene through key rotation. In Session B, security control was extended to container orchestration using a `kind` Kubernetes cluster, where workloads were logically isolated into `dev` and `prod` namespaces and restricted using scoped ServiceAccounts, Roles, and RoleBindings. Platform enforcement was rigorously validated via `kubectl auth can-i` testing, confirming that authorized actions were permitted while destructive operations and cross-namespace access were strictly blocked. Together, both sessions demonstrate a robust, multi-layered approach to identity management and least-privilege enforcement across cloud control planes and containerized runtime environments

---
## Session A

---

## 2. One-Time Environment Setup & Initial Identity

### 2.1 Service Initialization & Identity Mapping
LocalStack was started in a Docker container to simulate AWS IAM services locally on port `4566`. Dummy credentials were configured to establish the default caller identity.

1. **Verify Docker Status:** `docker --version`
2. **Start LocalStack:** `docker run -d --name localstack -p 4566:4566 localstack/localstack:3.0`
4. **Health Check Endpoint:** `curl http://localhost:4566/_localstack/health`
<img width="1882" height="252" alt="Screenshot 2026-07-31 224228" src="https://github.com/user-attachments/assets/209084fd-3739-4e66-856e-069b0f276c1a" />

5. **Configure Dummy Credentials & Endpoint Variable:**
   ```bash
   aws configure set aws_access_key_id test
   aws configure set aws_secret_access_key test
   aws configure set region us-east-1
   EP='--endpoint-url=http://localhost:4566'
   aws $EP sts get-caller-identity
   
<img width="1010" height="415" alt="Screenshot 2026-07-31 224337" src="https://github.com/user-attachments/assets/380441d1-a8e8-4c2d-bb16-0745900efac6" />

## 3. Task 1: Mapping the Cloud Identity Landscape

Understanding fundamental AWS IAM concepts and building blocks:

| Concept | AWS Term | Purpose |
| :--- | :--- | :--- |
| All-powerful owner | Root user | Complete administrative account created with the AWS environment; possesses unrestricted privileges and should not be used for daily tasks. |
| Human/app identity | IAM User | An identity created within AWS that represents a specific person or application needing interaction with AWS resources. |
| Permission bundle | IAM Policy | A JSON document explicitly defining allowed or denied permissions and actions on specific cloud resources. |
| Collection of users | IAM Group | A container for multiple IAM users that enables simplified, batch permission management across identities. |
| Temporary identity | IAM Role | An identity with dynamic credentials assumed temporarily by users, services, or applications to perform specific actions. |

## 4. Task 2: Create a Least-Privilege Admin (Stop Using Root)

To avoid using the root user, an `Admins` group was created with the `AdministratorAccess` policy attached[cite: 2]. A personal admin user was subsequently created and added to the group.

1. **Create Group & Attach Policy:**
   ```bash
   aws $EP iam create-group --group-name Admins
   aws $EP iam attach-group-policy --group-name Admins \
     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

<img width="762" height="353" alt="Screenshot 2026-07-31 224422" src="https://github.com/user-attachments/assets/b2a68c18-abba-4083-bec0-72ed0b37429a" />
<img width="767" height="98" alt="Screenshot 2026-07-31 224452" src="https://github.com/user-attachments/assets/611b71e1-3735-43df-94b1-382de40ec67d" />

2. **Create Personal Admin User & Assign Group Membership:**
   ```bash
   aws $EP iam create-user --user-name CloudAdmin_Ziyad
   aws $EP iam add-user-to-group --group-name Admins \
     --user-name CloudAdmin_Ziyad
   aws $EP iam get-group --group-name Admins

<img width="835" height="287" alt="Screenshot 2026-07-31 224527" src="https://github.com/user-attachments/assets/82914528-2270-49e2-8791-3536deaba060" />
<img width="720" height="97" alt="Screenshot 2026-07-31 224556" src="https://github.com/user-attachments/assets/273dcbc3-8782-4541-b2ba-dcac11ec036f" />
<img width="950" height="506" alt="Screenshot 2026-07-31 224615" src="https://github.com/user-attachments/assets/0b77e979-4920-4457-b255-8dcf6ebd0cde" />


## 5. Task 3: Enforce Least Privilege with a Scoped Policy

A read-only analyst user was established to demonstrate fine-grained authorization by restricting capabilities to S3 read operations only.

1. **Create Read-Only User & Attach Scoped Policy:**
   ```bash
   aws $EP iam create-user --user-name Analyst_Ziyad
   aws $EP iam attach-user-policy --user-name Analyst_Ziyad \
     --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
2. **List Attached Policies:**
   ```bash
   aws $EP iam list-attached-user-policies --user-name Analyst_Ziyad

<img width="807" height="295" alt="Screenshot 2026-07-31 224646" src="https://github.com/user-attachments/assets/6de69491-d2e5-4f99-9b1d-781429aa42e7" />
<img width="1057" height="357" alt="Screenshot 2026-07-31 224814" src="https://github.com/user-attachments/assets/5e44ce88-ab89-46ba-bb5e-50701200f475" />


**5.1 Blast Radius Reduction Analysis**
In the case that Analyst_Ziyad were compromised credentials the attacker could only read the content inside Amazon’s S3 bucket. This user is not able to write, update or remove any data from S3, neither would they be able to compromise, remove or alter EC2, I AM, or other cloud services.

## 6. Task 4: Credential Hygiene & Access Key Rotation

Programmatic access keys were generated for the Analyst account, followed by a key deactivation demonstration to illustrate proper credential lifecycle management.

1. **Create Access Key:**
   ```bash
   aws $EP iam create-access-key --user-name Analyst_Ziyad

2. **List Access Key:**
   ```bash
   aws $EP iam list-access-keys --user-name Analyst_Ziyad
   
3. **Deactivate Access Key (Rotation):**
   ```bash
   aws $EP iam update-access-key --user-name Analyst_Ziyad \
   --access-key-id <PASTE_ACCESS_KEY_ID> --status Inactive

<img width="800" height="315" alt="Screenshot 2026-07-31 224917" src="https://github.com/user-attachments/assets/4498e2ae-e518-4fad-ad12-3152d3774f1c" />
<img width="950" height="425" alt="Screenshot 2026-07-31 230011" src="https://github.com/user-attachments/assets/4e8bd1dd-f915-4844-b8d4-82ed98a8f534" />
---
## Session B

---

## 7. Environment Setup: Local Kubernetes Cluster

A local Kubernetes cluster named `ccse-lab1` was initialized inside Docker to evaluate RBAC enforcement mechanics.

1. **Create Cluster:**
   ```bash
   kind create cluster --name ccse-lab1
   kubectl cluster-info --context kind-ccse-lab1
   kubectl get nodes

<img width="1320" height="678" alt="Screenshot 2026-08-02 224017" src="https://github.com/user-attachments/assets/26c6441c-1bcc-4afe-be10-bf087f6ed717" />

## 8. Task 5: Separate Environments with Namespaces

Namespaces were created to logically partition resources into distinct development (dev) and production (prod) environments.

1. **Create Namespace:**
   ```bash
   kubectl create namespace dev
   kubectl create namespace prod

2. **List Namespace:**
   ```bash
   kubectl get namespaces

<img width="506" height="461" alt="Screenshot 2026-08-02 224130" src="https://github.com/user-attachments/assets/4bee0376-5f69-4166-b78c-dfa7a23f68a7" />


## 9. Task 6: Define a Role and Bind It (Least Privilege)

A ServiceAccount representing a developer was established in dev alongside a scoped Role permitting only read capabilities on Pods. The Role was bound to the ServiceAccount via a RoleBinding.

1. **Create ServiceAccount in dev:**
   ```bash
   kubectl create serviceaccount dev-user -n dev

2. **Create Read-Only Pod Role in dev:**
   ```bash
   kubectl create role pod-reader -n dev \
   --verb=get,list,watch --resource=pods

3. **Bind Role to ServiceAccount:**
   ```bash
   kubectl create rolebinding dev-user-binding -n dev \
   --role=pod-reader --serviceaccount=dev:dev-user

<img width="827" height="346" alt="Screenshot 2026-08-02 224258" src="https://github.com/user-attachments/assets/d22a031c-5fbe-4822-b8a2-5bbc28ac9e52" />

## 10. Task 7: Test That Access Control Works

The authorization boundary was evaluated using kubectl auth can-i impersonating the dev-user ServiceAccount (system:serviceaccount:dev:dev-user).
   
1. **Testing:**   
   ```bash
   SA='system:serviceaccount:dev:dev-user'

   # Test 1: List pods in dev namespace (Allowed)
   kubectl auth can-i list pods -n dev --as=$SA

   # Test 2: Delete pods in dev namespace (Denied)
   kubectl auth can-i delete pods -n dev --as=$SA

   # Test 2: Delete pods in dev namespace (Denied)
   kubectl auth can-i delete pods -n dev --as=$SA

<img width="675" height="361" alt="Screenshot 2026-08-02 225759" src="https://github.com/user-attachments/assets/614ce8d7-0cf7-4e81-b602-03f1f414903e" />

### 10.1. Authorization vs. Authentication Analysis

* **Authentication:** The ServiceAccount successfully authenticates its identity (`system:serviceaccount:dev:dev-user`) across all three evaluation checks, passing identity validation without credential errors.
* **Authorization:** The Kubernetes API server enforces strict authorization rules at both the action verb and namespace boundaries:
  * **Listing Pods in `dev` (`YES`):** Explicitly authorized by the `pod-reader` Role binding assigned to the ServiceAccount in the `dev` namespace.
  * **Deleting Pods in `dev` (`NO`):** Blocked because the `delete` verb is deliberately omitted from the `pod-reader` Role definition, enforcing read-only access.
  * **Listing Pods in `prod` (`NO`):** Blocked because the `pod-reader` Role and RoleBinding are strictly scoped to the `dev` namespace, leaving `prod` completely off-limits.

## 11. Verification Command Deliverable

3. **Verification YAML dump of the active RoleBinding configuration:**
   ```bash
   kubectl get rolebinding dev-user-binding -n dev -o yaml


<img width="792" height="458" alt="Screenshot 2026-08-02 230602" src="https://github.com/user-attachments/assets/ad0f9ed2-1481-42cc-b70b-bf6767a5f175" />

## 12. Short-Answer Questions & Deliverables

### Q1. Why is attaching policies to groups better than attaching them directly to users?
**Answer:** Attaching policies to groups simplifies administrative overhead and ensures scalable authorization management. When role permissions change, modifying a single group policy automatically updates privileges for all associated users, reducing human error, preventing permission drift, and maintaining auditability across the organization.

### Q2. What is the difference between an IAM User and an IAM Role?
**Answer:** An **IAM User** represents an identity (person or application) with permanent long-lived credentials (passwords or access keys). An **IAM Role** is an identity assumed temporarily by trusted users, applications, or services to acquire dynamic, short-lived credentials for specific operational tasks.

### Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.
**Answer:** Least privilege ensures identities receive only the minimum access necessary for their function. Granting the Analyst account only `AmazonS3ReadOnlyAccess` prevents actions like resource deletion or privilege escalation. If compromised, the blast radius is strictly limited to reading S3 data, safeguarding core infrastructure from destruction.

### Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?
**Answer:** A **Role** is an object defining a set of permission rules (allowed API groups, resources, and verbs) within a specific namespace[cite: 1]. A **RoleBinding** connects that Role to a subject (User, Group, or ServiceAccount), granting defined permissions to that specific entity in that namespace.

### Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?
**Answer:** Access failed because the Role and RoleBinding were created exclusively within the `dev` namespace. Kubernetes RBAC enforces strict namespace boundaries unless explicitly granted via ClusterRoles or local namespace bindings. This demonstrates **Least Privilege** and **Compartmentalization (Defense in Depth)**.

## 13. Overall Lab Deliverables Summary

| Session | Task / Verification Objective | Command / Test Executed | Expected Result / Status |
| :--- | :--- | :--- | :---: |
| **Session A** | LocalStack Identity Verification | `aws $EP sts get-caller-identity`[cite: 1] | ✅ Pass[cite: 1] |
| **Session A** | Admin Group & User Membership | `aws $EP iam get-group --group-name Admins`[cite: 1] | ✅ Pass[cite: 1] |
| **Session A** | Analyst Policy Scoping (S3 Read-Only) | `aws $EP iam list-attached-user-policies --user-name Analyst_Ziyad`[cite: 1] | ✅ Pass[cite: 1] |
| **Session A** | Access Key Rotation & Deactivation | `aws $EP iam list-access-keys --user-name Analyst_Ziyad`[cite: 1] | ✅ Pass[cite: 1] |
| **Session B** | Kubernetes Cluster Readiness | `kubectl get nodes`[cite: 1] | ✅ Pass[cite: 1] |
| **Session B** | Environment Separation | `kubectl get namespaces`[cite: 1] | ✅ Pass[cite: 1] |
| **Session B** | RBAC Read Test (`dev` Pods) | `kubectl auth can-i list pods -n dev --as=$SA`[cite: 1] | ✅ Pass (YES)[cite: 1] |
| **Session B** | RBAC Privilege Restriction (`dev` Pods) | `kubectl auth can-i delete pods -n dev --as=$SA`[cite: 1] | ✅ Pass (NO)[cite: 1] |
| **Session B** | RBAC Namespace Isolation (`prod` Pods) | `kubectl auth can-i list pods -n prod --as=$SA`[cite: 1] | ✅ Pass (NO)[cite: 1] |
| **Session B** | RoleBinding Configuration Dump | `kubectl get rolebinding dev-user-binding -n dev -o yaml`[cite: 1] | ✅ Pass[cite: 1] |

## 14. Conclusion

This lab successfully validated the core principles of identity governance and platform-enforced authorization across cloud control planes and container orchestration environments. In Session A, AWS IAM concepts were applied using LocalStack by replacing risky root usage with group-based administrator access, scoping read-only permissions for analyst roles to minimize blast radius, and demonstrating proper credential hygiene through access key deactivation. In Session B, Kubernetes RBAC mechanics were established within a `kind` cluster, proving that logical namespace separation combined with tightly scoped Roles and RoleBindings effectively restricts workload capabilities. Rigorous authorization testing confirmed that authorized operations succeeded while destructive actions and cross-namespace access were strictly blocked, together illustrating a comprehensive, defense-in-depth approach to cloud security and least-privilege enforcement.


















