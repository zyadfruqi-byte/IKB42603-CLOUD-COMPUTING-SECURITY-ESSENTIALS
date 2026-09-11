# IKB42603 Cloud Computing Security Essentials
## Lab Report 6: Object Storage Security & Data Security Lifecycle

**Prepared by:** Ziyad Faruqi Bin Harith Faruqi 
**Course:** IKB42603 Cloud Computing Security Essentials  
**Date:** 11/9/2026  
**Environment:** Kali Linux VM

---

## 1. Executive Summary
This laboratory exercise demonstrates the configuration, auditing, and hardening of cloud object storage (Amazon S3 emulated via LocalStack) across the full Data Security Lifecycle. **Session A** addresses the exposure vector behind public bucket breaches. It covers data classification tagging, reproducing public exposure via wild-card resource policies, enforcing preventive guardrails through Block Public Access, and testing conflict resolution between Identity (IAM) and Resource (Bucket) policies. **Session B** implements data protection and lifecycle controls, including default server-side encryption with AWS KMS (SSE-KMS), temporary access delegation via presigned URLs, analyzing object-level data remanence with versioning and delete markers, and enforcing automated retention alongside provable deletion via cryptographic erasure.

---

## 2. Environment Setup & Prerequisites
* **Operating System:** Linux / macOS / Windows (WSL2 / Git Bash)
* **Container Runtime:** Docker Engine / Docker Desktop
* **Cloud Emulation:** LocalStack Pro (`localstack/localstack-pro:latest`) with `ENFORCE_IAM=1` enabled on port 4566
* **Client Tools:** AWS CLI v2, `curl`, POSIX standard utilities (`jq`, `cat`, `echo`, `head`)

```bash
# Environment Setup Execution
docker rm -f localstack 2>/dev/null
docker run -d --name localstack -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN=$LOCALSTACK_AUTH_TOKEN \
  -e ENFORCE_IAM=1 \
  localstack/localstack-pro:latest

export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1
aws $EP sts get-caller-identity
```

<img width="585" height="196" alt="Screenshot 2026-09-11 200942" src="https://github.com/user-attachments/assets/8b6f7c77-66b3-422c-96b6-aefaf72ecb86" />

---

## 3. Implementation & Results

### Session A: Object Storage & the Exposure Problem (Week 11)

#### Task 1: Data Classification & Tagging
A unique S3 bucket was created to store three objects corresponding to different data sensitivity levels, each tagged with its classification metadata.

```bash
# Bucket Provisioning
export BUCKET="miit-patient-records-$RANDOM"
aws $EP s3api create-bucket --bucket $BUCKET

# Generate Sample Files
echo 'Ward visiting hours 10am-8pm' > public-notice.txt
echo 'Staff duty schedule, week 12' > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential' > confidential-record.txt

# Upload Objects with Classification Tags
aws $EP s3api put-object --bucket $BUCKET --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'

aws $EP s3api put-object --bucket $BUCKET --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'

# Verification Commands
aws $EP s3api list-objects-v2 --bucket $BUCKET \
  --query 'Contents[].[Key, Size]' --output table

aws $EP s3api get-object-tagging --bucket $BUCKET --key confidential/record.txt
```

**Output Verification:**
<img width="616" height="118" alt="Screenshot 2026-09-11 200959" src="https://github.com/user-attachments/assets/948591e6-b02c-46a6-90e3-97c2dfdc965d" />
<img width="631" height="147" alt="Screenshot 2026-09-11 201014" src="https://github.com/user-attachments/assets/335142c5-3d82-4ea8-bcfd-ad1cf11ad0dd" />
<img width="1037" height="130" alt="Screenshot 2026-09-11 201032" src="https://github.com/user-attachments/assets/28cc6f49-3ac0-4a7e-bcfc-ad7f0f1ebd69" />
<img width="1810" height="476" alt="Screenshot 2026-09-11 201235" src="https://github.com/user-attachments/assets/1613a5cd-7cff-4647-b800-d1d5d3a900f9" />
<img width="678" height="267" alt="Screenshot 2026-09-11 201303" src="https://github.com/user-attachments/assets/487c89e8-3d3d-4b95-899a-4b102c0d1dea" />
<img width="1070" height="281" alt="Screenshot 2026-09-11 201315" src="https://github.com/user-attachments/assets/9c06f467-f554-454d-9d00-80350de18600" />


#### Task 2: Reproducing the Public Bucket Breach
An overly permissive bucket policy containing `"Principal": "*"` was applied to the bucket, allowing unauthenticated anonymous access to confidential records.

```bash
cat > public-policy.json <<JSON
{
 "Version": "2012-10-17",
 "Statement": [{
 "Sid": "PublicReadEverything",
 "Effect": "Allow",
 "Principal": "*",
 "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::$BUCKET/*"
 }]
}
JSON
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text

# The attacker's view: no AWS credentials, no CLI, just a URL
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
 http://localhost:4566/$BUCKET/confidential/record.txt
cat leaked.txt
```

**Output Verification:**
<img width="1110" height="355" alt="Screenshot 2026-09-11 201342" src="https://github.com/user-attachments/assets/75e94d24-27c4-4588-9fd8-f7c14aea3ba5" />
<img width="707" height="180" alt="Screenshot 2026-09-11 201406" src="https://github.com/user-attachments/assets/7f0e42e6-98a8-4f40-8469-1b103398d8c4" />


#### Task 3: Remediation with Block Public Access
The vulnerable public bucket policy was deleted and account-level Block Public Access guardrails were enabled. A least-privilege bucket policy was then applied to restrict read access strictly to internal prefixes for the account owner identity.

```bash
# 1. Remove the offending policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET
# 2. Apply the account-level guardrail to the bucket
aws $EP s3api put-public-access-block --bucket $BUCKET \
 --public-access-block-configuration \

BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws $EP s3api get-public-access-block --bucket $BUCKET
# 3. Try to re-introduce the public policy - the guardrail should refuse it
aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://public-policy.json
# 4. Re-test the anonymous read
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
 http://localhost:4566/$BUCKET/confidential/record.txt

 ```

**Output Verification:**
<img width="1242" height="122" alt="Screenshot 2026-09-11 201548" src="https://github.com/user-attachments/assets/5194c578-3c57-47c5-89ec-ec28273bbe11" />
<img width="767" height="268" alt="Screenshot 2026-09-11 201601" src="https://github.com/user-attachments/assets/adb3e5dc-0b30-4dfb-bf4c-2ebefcc3427d" />
<img width="922" height="121" alt="Screenshot 2026-09-11 201747" src="https://github.com/user-attachments/assets/641ff5d7-1797-4297-a150-041e9dda42ec" />


Write the policy you should have had: read access for your own account only, scoped to the
internal prefix:

```bash
cat > least-privilege-policy.json <<JSON
{
 "Version": "2012-10-17",
 "Statement": [{
 "Sid": "AccountReadInternalOnly",
 "Effect": "Allow",
 "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
 "Action": "s3:GetObject",
 "Resource": "arn:aws:s3:::$BUCKET/internal/*"
 }]

 }
 JSON
 aws $EP s3api put-bucket-policy --bucket $BUCKET --policy file://least-privilegepolicy.json
 aws $EP s3api get-bucket-policy --bucket $BUCKET --query Policy --output text
```

**Output Verification:**
<img width="1191" height="397" alt="Screenshot 2026-09-11 201940" src="https://github.com/user-attachments/assets/30d4263b-6e94-4a72-903c-59c149719921" />
<img width="1597" height="95" alt="Screenshot 2026-09-11 202003" src="https://github.com/user-attachments/assets/7be422e0-45a0-4d18-a340-26d7f900b3f7" />


#### Task 4: Identity Policy vs. Resource Policy
An IAM user (`DataAnalyst`) with full S3 read permissions was created to demonstrate policy conflict evaluation[cite: 3]. A bucket resource policy containing an explicit `Deny` statement on the `confidential/*` prefix was applied[cite: 3]. The evaluation proved that an explicit `Deny` in a resource policy overrides an explicit `Allow` in an identity policy[cite: 3].

```bash
# 1. Create IAM User
aws $EP iam create-user --user-name DataAnalyst

# 2. Attach Full Read-Only Identity Policy
cat > analyst-iam.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
JSON

aws $EP iam put-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll --policy-document file://analyst-iam.json

# 3. Generate Credentials and Configure Named CLI Profile
KEYS=$(aws $EP iam create-access-key --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
ANALYST_KEY_ID=$(echo $KEYS | awk '{print $1}')
ANALYST_SECRET=$(echo $KEYS | awk '{print $2}')

aws configure --profile analyst set aws_access_key_id "$ANALYST_KEY_ID"
aws configure --profile analyst set aws_secret_access_key "$ANALYST_SECRET"
aws configure --profile analyst set region us-east-1

# 4. Apply Conflicting Bucket Resource Policy
cat > deny-confidential.json <<JSON "2012-10-17", "Action": "Allow", "AllowAnalystInternal", "Deny", "DenyAnalystConfidential", "Effect": "Principal": "Resource": "Sid": "Statement": "Version": "arn:aws:iam::000000000000:user/DataAnalyst"}, "arn:aws:s3:::$BUCKET/confidential/*" "arn:aws:s3:::$BUCKET/internal/*" "confidential: "internal: "s3:*", "s3:GetObject",
```

**Output Verification:**
<img width="773" height="298" alt="Screenshot 2026-09-11 202023" src="https://github.com/user-attachments/assets/8f7bc510-ab66-4da9-a0b9-202ce3a83f1f" />
<img width="892" height="377" alt="Screenshot 2026-09-11 202045" src="https://github.com/user-attachments/assets/af32abd3-43b9-432c-8be3-61e456e8272f" />
<img width="937" height="125" alt="Screenshot 2026-09-11 202116" src="https://github.com/user-attachments/assets/78a46e15-ec04-44c1-91c7-82be1cafd565" />
<img width="960" height="115" alt="Screenshot 2026-09-11 202132" src="https://github.com/user-attachments/assets/42b11821-e2ee-48d2-a6bf-44787bcdbf24" />
<img width="1215" height="650" alt="Screenshot 2026-09-11 202156" src="https://github.com/user-attachments/assets/1920cfc3-f6df-4278-a92e-204e209e3a26" />
<img width="1780" height="337" alt="Screenshot 2026-09-11 202216" src="https://github.com/user-attachments/assets/c17220b7-c883-4ce6-8c3b-fc968c4424ee" />
<img width="1816" height="315" alt="Screenshot 2026-09-11 202231" src="https://github.com/user-attachments/assets/61bfac9b-9599-49d6-a3f3-a3f6ecf4a909" />


### Session B: Protecting, Retaining, and Retiring Data (Week 12)

#### Task 5: Default Encryption at Rest (SSE-KMS)
A customer-managed KMS key was created, and default server-side encryption using SSE-KMS with Bucket Key optimization was enforced on the bucket.

```bash
# Provision Customer-Managed Key in KMS
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)

# Define Bucket Server-Side Encryption Configuration
cat > encryption.json <<JSON "$KEY_ID" "$URL" "ApplyServerSideEncryptionByDefault": "BucketKeyEnabled": "KMSMasterKeyID": "Rules": "SSEAlgorithm": "aws:kms",
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt --body rec-v2.txt
aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt --body rec-v3.txt

# Execute Object Deletion (Creates a Delete Marker)
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt

# Inspect Versions and Delete Markers
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId, IsLatest]' --output table

# Attempt standard retrieve (Fails with 404 / NoSuchKey)
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt gone.txt || echo "Standard GET: File Not Found"

# Recover data by targeting the unversioned/original Version ID
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt
cat recovered.txt

# Permanently purge the specific version
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt --version-id null
```

**Output Verification:**
<img width="1808" height="118" alt="Screenshot 2026-09-11 202304" src="https://github.com/user-attachments/assets/cc728f5b-b91a-4d18-b591-e9316131fc93" />
<img width="1490" height="380" alt="Screenshot 2026-09-11 202320" src="https://github.com/user-attachments/assets/9fae9c19-6309-4f8d-8de1-2a5875492b5e" />
<img width="1880" height="282" alt="Screenshot 2026-09-11 202338" src="https://github.com/user-attachments/assets/6c2f3de0-6ff3-457f-a372-aa73e04cc846" />


#### Task 6: Delegated Access and the Condition-Key Trap
A presigned URL was generated to delegate time-bounded read access to an unauthenticated caller. Next, an `aws:SecureTransport` policy was tested to observe the lockout impact when applied against a plain HTTP endpoint.

```bash
# 1. Generate Presigned URL valid for 60 seconds
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60

# Paste URL to variable for verification
URL='PASTE_PRESIGNED_URL_HERE'
curl -s -w ' HTTP %{http_code}\n' "$URL"

# Wait for URL expiration and re-test
sleep 65
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"

# 2. Apply Enforce TLS / SecureTransport Bucket Policy
cat > secure-transport.json <<JSON "*", "2012-10-17", "Action": "Condition": "Deny", "DenyUnencryptedTransport", "Effect": "Principal": "REQUEST "Resource": "Sid": "Statement": "Version": "arn:aws:s3:::$BUCKET/*"], "false"}} "s3:*", # $BUCKET $EP (AccessDenied) (Expect **Output --bucket --policy 12 200 3. 4. 403 API Access AccessDenied An BLOCKED: Denied HTTP JSON ListObjectsV2 Non-TLS REQUEST Recover Staff Test Verification:** ["arn:aws:s3:::$BUCKET", [{ ``` ```` ```text after aws by calling delete-bucket-policy detected detected" duty echo endpoint error expiry: file://secure-transport.json list-objects-v2 lock-out) occurred operation operation: over policy put-bucket-policy removing s3api schedule, the transport week when { {"Bool": {"aws:SecureTransport": || } }]>
```

**Output Verification:**
<img width="1011" height="146" alt="Screenshot 2026-09-11 202351" src="https://github.com/user-attachments/assets/8995c20c-6648-4730-9e81-5d47ca361e5f" />
<img width="877" height="372" alt="Screenshot 2026-09-11 202404" src="https://github.com/user-attachments/assets/3caf1c4f-de07-4ceb-8ef2-e7ecc0af1c5d" />
<img width="900" height="762" alt="Screenshot 2026-09-11 202450" src="https://github.com/user-attachments/assets/65d9c735-3a02-4f9e-bd1e-22bbc6caa184" />
<img width="902" height="770" alt="Screenshot 2026-09-11 202515" src="https://github.com/user-attachments/assets/5e6527a6-c698-4374-b540-8fa23657fee4" />
<img width="747" height="343" alt="Screenshot 2026-09-11 202525" src="https://github.com/user-attachments/assets/70cc2aa3-95a4-44f7-b1b6-789b2c803d91" />
<img width="687" height="70" alt="Screenshot 2026-09-11 202543" src="https://github.com/user-attachments/assets/ea343154-f041-4d6e-ab6e-a35ce3d8e1b2" />


#### Task 7: Versioning, Delete Markers & Data Remanence
Bucket versioning was enabled to observe object-level data remanence. Multiple revisions of a confidential patient record were uploaded, followed by an object deletion command. The test demonstrated that standard deletion merely places a delete marker, leaving all previous unredacted versions recoverable.

```bash
# 1. Enable Bucket Versioning
aws $EP s3api put-bucket-versioning --bucket $BUCKET \
  --versioning-configuration Status=Enabled

aws $EP s3api get-bucket-versioning --bucket $BUCKET

# 2. Upload Two More Revisions of the Confidential Record
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]' > rec-v3.txt

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text

aws $EP s3api put-object --bucket $BUCKET --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text

# List all stored object versions
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId, IsLatest, Size]' --output table

# 3. Perform Standard Deletion (Writes a Delete Marker)
aws $EP s3api delete-object --bucket $BUCKET --key confidential/record.txt

# Inspect active Delete Markers
aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId, IsLatest]' --output table

# Attempt standard GET request (Fails with 404 / NoSuchKey)
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt gone.txt || echo "Standard GET: File Not Found"

# 4. Recover Original Unredacted Version (Targeting pre-versioning 'null' Version ID)
aws $EP s3api get-object --bucket $BUCKET --key confidential/record.txt \
  --version-id null recovered.txt

cat recovered.txt

# 5. Permanently Purge Specific Version by Version ID
aws $EP s3api delete-object --bucket $BUCKET \
  --key confidential/record.txt --version-id null

aws $EP s3api list-object-versions --bucket $BUCKET \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId, Size]' --output table
```
**Output Verification:**
<img width="1427" height="617" alt="Screenshot 2026-09-11 202623" src="https://github.com/user-attachments/assets/f479a6a8-cfcd-4364-ba81-4de224b0721e" />
<img width="1017" height="165" alt="Screenshot 2026-09-11 202640" src="https://github.com/user-attachments/assets/024c158a-8d1f-4f7e-ae69-d230b91b1909" />
<img width="1482" height="121" alt="Screenshot 2026-09-11 202659" src="https://github.com/user-attachments/assets/3517360d-6ff0-4496-b289-3be471f012e7" />
<img width="1385" height="391" alt="Screenshot 2026-09-11 202718" src="https://github.com/user-attachments/assets/bb4db204-efb2-4143-b1f9-7f0ced1d5f5c" />
<img width="1237" height="145" alt="Screenshot 2026-09-11 202735" src="https://github.com/user-attachments/assets/809871c6-a69a-473b-8100-1513af043476" />


#### Task 8: Lifecycle, Retention & Cryptographic Erasure
An automated lifecycle retention policy was configured to enforce non-current version expiration and clear incomplete multipart uploads. Cryptographic erasure was then executed by disabling and scheduling the deletion of the KMS master key, rendering all encrypted objects permanently unrecoverable.

```bash
# 1. Apply Lifecycle Configuration Policy
cat > lifecycle.json <<'JSON'
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }
  ]
}
JSON

aws $EP s3api put-bucket-lifecycle-configuration --bucket $BUCKET \
  --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID, Status]' --output table

# 2. Inspect KMS Key Status Prior to Erasure
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyId, KeyState, Enabled]' --output text

# 3. Execute Cryptographic Erasure (Disable Key & Schedule Deletion)
aws $EP kms disable-key --key-id $KEY_ID
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# Verify Updated Key Metadata State
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState, DeletionDate]' --output text

# 4. Attempt to Read Encrypted Object (Fails due to disabled KMS key)
aws $EP s3api get-object --bucket $BUCKET \
  --key confidential/record-v2.txt after-erasure.txt
```

**Output Verification:**
<img width="1557" height="575" alt="Screenshot 2026-09-11 202757" src="https://github.com/user-attachments/assets/c7d4c634-e6c4-4e69-b7fd-53fc0aebb10d" />
<img width="1336" height="286" alt="Screenshot 2026-09-11 202814" src="https://github.com/user-attachments/assets/243d5a03-a995-4af9-a905-553a96dc4907" />
<img width="1347" height="416" alt="Screenshot 2026-09-11 202936" src="https://github.com/user-attachments/assets/626d7b81-14d7-4952-86f8-6198c182e359" />


---

## 4. Data Classification Table

| Classification | Who May Read It | Impact If Leaked | Control Applied in Lab |
| :--- | :--- | :--- | :--- |
| **Public** | Anonymous Internet users, external clients, public. | None; public domain information. | Stored under `public/` prefix with basic read access. |
| **Internal** | Authenticated employees, internal staff, active duty personnel. | Low to Moderate; internal process exposure, minor operational risk. | Restricted via Least-Privilege Policy to authenticated account identity (`arn:aws:iam::000000000000:root`) under `internal/*` prefix. |
| **Confidential** | Authorized clinical staff and medical personnel on a need-to-know basis. | High to Critical; severe regulatory violation (PDPA/GDPR), reputation damage, patient privacy breach. | Block Public Access enabled, explicit IAM `Deny` rules applied, default SSE-KMS envelope encryption, and Lifecycle Cryptographic Erasure capability. |

---

## 5. Short-Answer Questions

### Q1. Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?
* **Element:** The `"Principal": "*"` declaration in the statement caused the exposure.
* **Impact Comparison:** On an identity policy, an over-broad permission (e.g., `Action: "*"`) only grants rights to the specific user or role to which the policy is attached. On a resource-based bucket policy, `"Principal": "*"` waives all authentication requirements account-wide, opening public, unauthenticated read access to the entire Internet without needing valid AWS credentials.

### Q2. Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?
* **Identity-Based Policy:** Attached directly to IAM entities (users, groups, roles) to define what actions the identity can perform across cloud resources.
* **Resource-Based Policy:** Attached directly to the cloud resource (e.g., S3 Bucket) to specify who (which principals) can access that specific resource and under what conditions.
* **Task 4 Decision Logic:**
  1. *Request for `internal/roster.txt`:* Decided by **both policies matching with `Allow`** (IAM Policy granted `s3:GetObject` and Bucket Policy permitted `internal/*`).
  2. *Request for `confidential/record.txt`:* Decided by the **Resource-Based Bucket Policy**. Although the identity policy allowed access, the explicit `"Effect": "Deny"` in the bucket policy took precedence, immediately denying the request.

### Q3. Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?
* **Control vs. Guardrail:** A *control* (like a bucket policy) configures permission logic for a specific resource, but remains vulnerable to human error, misconfiguration, or accidental deletion by developers. A *guardrail* (like Block Public Access) is an account or bucket-level safety override that enforces a hard preventative boundary, blocking any public policy or ACL from taking effect even if a developer explicitly writes `"Principal": "*"`.
* **Organizational Importance:** In large engineering environments with decentralized deployments, guardrails prevent human error and misconfigurations from causing data breaches, without requiring security teams to manually audit every individual bucket configuration.

### Q4. Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.
* **Protection Status:** No, SSE-KMS does not protect the record from an authorized identity if that identity also possesses permissions to use the underlying KMS decryption key (`kms:Decrypt`).
* **What SSE-KMS Defends Against:** Protects against physical media theft, unauthorized provider-level disk access, raw storage scraping, and unencrypted snapshot exposure at rest.
* **What SSE-KMS Does NOT Defend Against:** It does not replace logical Access Control (IAM/Bucket policies). If a caller has valid S3 read permissions and authorization to use the KMS key, S3 automatically decrypts the object transparently during retrieval.

### Q5. A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.
* **Why `delete-object` fails compliance:** When versioning is enabled, issuing a standard `delete-object` request only places a lightweight *Delete Marker* as the latest revision. All prior versions containing sensitive data remain intact and can be retrieved using `--version-id`, violating privacy regulations (e.g., PDPA, GDPR).
* **Two Provable Deletion Mechanisms:**
  1. *Explicit Multi-Version Purge:* Iterating through and executing permanent per-version deletions targeting every specific Version ID (`delete-object --version-id <ID>`).
  2. *Cryptographic Erasure (Crypto-Shredding):* Destroying or permanently disabling the customer-managed KMS key used to encrypt the data. Without the key, the stored ciphertext becomes unrecoverable mathematical noise, providing provable deletion across all copies, back-ups, and versions simultaneously.

### Q6. You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.
1. `aws s3api get-public-access-block --bucket <BUCKET>`
   * *Control Evidenced:* Demonstrates enforcement of preventive public access boundaries and account-wide guardrails (ISO 27001 / SOC 2 Network Exposure Prevention).
2. `aws s3api get-bucket-encryption --bucket <BUCKET>`
   * *Control Evidenced:* Proves mandatory encryption-at-rest using customer-managed keys (SSE-KMS) across all stored objects (Data Protection & Cryptographic Controls).
3. `aws s3api get-bucket-lifecycle-configuration --bucket <BUCKET>`
   * *Control Evidenced:* Validates automated data retention, non-current version expiration, and lifecycle disposal compliance policies.


## 6. Verification Commands & Outputs

To confirm the final security posture of the bucket, the verification script was executed:

```bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="
aws $EP s3api get-public-access-block --bucket $BUCKET \
  --query 'PublicAccessBlockConfiguration' --output text

aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text

aws $EP s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' \
  --output text

aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID, Status]' --output table

aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.KeyState' --output text
```

**Verification Output:**
<img width="1872" height="387" alt="Screenshot 2026-09-11 203016" src="https://github.com/user-attachments/assets/82764d86-82b2-4ac3-b6ed-ae55c114035c" />


---

## 7. Security Best-Practices Checklist

| Security Control | Implementation Status | Lab Verification Evidence |
| :--- | :---: | :--- |
| **Data Classification & Tagging** | Checked | Every object tagged with classification metadata (`public`, `internal`, `confidential`) prior to access configuration (Task 1). |
| **No Public Anonymous Access** | Checked | Verified removal of `"Principal": "*"` policies; anonymous curl returned HTTP 403 (Tasks 2 & 3). |
| **Block Public Access Enabled** | Checked | All four flags (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) set to `true` (Task 3). |
| **Least-Privilege Resource Policies** | Checked | Access restricted to specific account roots and scoped explicitly to key prefixes (`internal/*`) (Task 3). |
| **Default SSE-KMS Encryption** | Checked | Configured default bucket-wide encryption using AWS KMS customer-managed key with Bucket Key enabled (Task 5). |
| **Secure Delegated Sharing** | Checked | Temporary object sharing restricted to short-lived time-bounded presigned URLs (Task 6). |
| **Versioning & Remanence Awareness** | Checked | Enabled bucket versioning; verified that delete markers leave prior versions retrievable until purged (Task 7). |
| **Lifecycle & Cryptographic Erasure** | Checked | Applied automated lifecycle retention rules; demonstrated provable deletion via KMS key deactivation (Task 8). |

---

## 8. Cleanup & Teardown

```bash
# 1. Delete Bucket Policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# 2. Purge All Object Versions
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: Versions[].{Key: Key, VersionId: VersionId}}')"

# 3. Purge All Delete Markers
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: DeleteMarkers[].{Key: Key, VersionId: VersionId}}')"

# 4. Remove Bucket & IAM Configurations
aws $EP s3api delete-bucket --bucket $BUCKET
aws $EP iam delete-user-policy --user-name DataAnalyst --policy-name S3ReadAll
aws $EP iam delete-user --user-name DataAnalyst

# 5. Stop LocalStack Container and Remove Local Artifacts
docker rm -f localstack 2>/dev/null
rm -f *.json *.txt
```
