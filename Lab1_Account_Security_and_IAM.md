# Lab 1 Report: Cloud Account Security, Identity & Access Management (Session A)

**Prepared by:** Ziyad Faruqi Bin Harith Faruqi

**Course:** IKB42603 Cloud Computing Security Essentials  
**Date:** 29/7/2026

**Environment:** Kali Linux VM (VirtualBox)  

---

## 1. Executive Summary
This report documents the execution of Lab 1 (Session A), focusing on cloud identity governance and the principle of least privilege using LocalStack IAM. Key tasks completed include initializing LocalStack, creating a scoped administrator account via group policy attachment, enforcing least privilege for an analyst identity, and practicing credential hygiene through access key lifecycle management.

---

## 2. One-Time Environment Setup & Initial Identity

### 2.1 Service Initialization & Identity Mapping
LocalStack was started in a Docker container to simulate AWS IAM services locally on port `4566`. Dummy credentials were configured to establish the default caller identity.

1. **Verify Docker Status:** `docker --version`
2. **Start LocalStack:** `docker run -d --name localstack -p 4566:4566 localstack/localstack`
3. **Health Check Endpoint:** `curl http://localhost:4566/_localstack/health`
4. **Configure Dummy Credentials & Endpoint Variable:**
   ```bash
   aws configure set aws_access_key_id test
   aws configure set aws_secret_access_key test
   aws configure set region us-east-1
   EP='--endpoint-url=http://localhost:4566'
   aws $EP sts get-caller-identity