# Lab 1 Report: Cloud Account Security, Identity & Access Management

**Prepared by:** Ziyad Faruqi Bin Harith Faruqi

**Course:** IKB42603 Cloud Computing Security Essentials  
**Date:** 29/7/2026

**Environment:** Kali Linux VM (VirtualBox)  

---

## 1. Executive Summary
This report documents the execution of Lab 1 (Session A), focusing on cloud identity governance and the principle of least privilege using LocalStack IAM. Key tasks completed include initializing LocalStack, creating a scoped administrator account via group policy attachment, enforcing least privilege for an analyst identity, and practicing credential hygiene through access key lifecycle management.

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

<img width="807" height="295" alt="Screenshot 2026-07-31 224646" src="https://github.com/user-attachments/assets/6de69491-d2e5-4f99-9b1d-781429aa42e7" />
<img width="1057" height="357" alt="Screenshot 2026-07-31 224814" src="https://github.com/user-attachments/assets/5e44ce88-ab89-46ba-bb5e-50701200f475" />

2. **List Attached Policies:**
   ```bash
   aws $EP iam list-attached-user-policies --user-name Analyst_Ziyad

<img width="800" height="315" alt="Screenshot 2026-07-31 224917" src="https://github.com/user-attachments/assets/1e9eec26-4855-4489-8b6f-cd456547ce32" />

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

