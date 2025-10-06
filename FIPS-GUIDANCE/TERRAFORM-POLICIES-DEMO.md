# Terraform Policies-as-Code Demo

**For customers interested in Infrastructure-as-Code and Policy-as-Code**

---

## 🎯 The Value Proposition

> "All our Image Assurance, Kubernetes Assurance, and Runtime Policies were designed and built in **Terraform (HCL format)** and imported directly into Aqua with appropriate scopes and enforcement ready out-of-the-box."

**Why this matters:**
- ✅ **Version controlled** - Policies tracked in Git, full audit history
- ✅ **Repeatable** - Deploy identical policies across environments
- ✅ **Testable** - Validate policy changes before deployment
- ✅ **Automated** - CI/CD integration for policy lifecycle
- ✅ **Self-documenting** - HCL is human-readable and declarative

---

## 📦 What We Built

### 6 Terraform-Managed Policies

```
policies/
├── golden-image-enforcement.tf        ⭐ Image Assurance (Admission Control)
├── fips-image-assurance-policy.tf     ⭐ Image Assurance (Pipeline Gate)
├── fips-kubernetes-policy.tf          ⭐ Kubernetes Assurance (Workload Compliance)
├── fips-runtime-policy.tf             ⭐ Container Runtime Policy (Behavioral Monitoring)
├── CIS.tf                             ⭐ CIS Benchmarks (Optional)
└── [REGO policies]                     Custom logic for PSS and CBOM
    ├── check_pss_restricted.rego
    ├── fips-compliance-cdx16.rego
    └── fips-compliance-image-assurance.rego
```

---

## 🎬 Demo Flow (5-7 minutes)

### Part 1: Show the Policy Files (2 min)

**Script:**
> "Let me show you how we define security policies as code. These aren't configured through a UI - they're Terraform files that we can version control, review, and deploy programmatically."

**Command:**
```bash
cd /Users/home/Developer/CBOM/policies

# Show the structure
ls -lh *.tf

# Display a key policy
cat golden-image-enforcement.tf
```

**Expected Output:**
```hcl
resource "aquasec_image_assurance_policy" "prod_golden_image_enforcement" {
  name        = "prod-golden-image-enforcement"
  description = "FIPS 140-3 Golden Image Registry Enforcement..."

  application_scopes = ["prod-namespace"]

  allowed_registries = {
    allowed_registries = [
      "aquacsacr.azurecr.io",
      "registry.access.redhat.com",
      "registry.customer.com",
      "ironbank.dso.mil"
    ]
  }

  block_failed = true  # ← BLOCKS at admission time
}
```

**Talking Points:**
- "This policy **blocks any image not from our approved registries** at deployment time"
- "Notice `application_scopes = ['prod-namespace']` - policies are scoped to specific environments"
- "The `block_failed = true` means Aqua's admission webhook **rejects the deployment** before the pod is created"

---

### Part 2: Show Policy Organization (1 min)

**Command:**
```bash
# Show all policies
grep -r "resource \"aquasec" *.tf | grep -v "^#" | cut -d'"' -f2 | sort -u
```

**Expected Output:**
```
aquasec_image_assurance_policy
aquasec_function_runtime_policy
aquasec_container_runtime_policy
```

**Script:**
> "We have three types of policies managed as code:
> 1. **Image Assurance** - Scans and blocks at build/deploy time
> 2. **Kubernetes Assurance** - Validates workload configuration
> 3. **Container Runtime** - Monitors behavior during execution"

---

### Part 3: Terraform Deployment Process (2 min)

**Show the Terraform workflow:**

```bash
# Initialize Terraform
terraform init

# Preview changes (safe - shows what would happen)
terraform plan

# Apply policies to Aqua (would require credentials)
# terraform apply
```

**Script:**
> "When we run `terraform apply`, these policies are automatically created in Aqua with all the controls, scopes, and REGO logic configured. No manual clicking through the UI."

**Show sample plan output:**
```
Terraform will perform the following actions:

  # aquasec_image_assurance_policy.prod_golden_image_enforcement will be created
  + resource "aquasec_image_assurance_policy" "prod_golden_image_enforcement" {
      + name               = "prod-golden-image-enforcement"
      + application_scopes = ["prod-namespace"]
      + block_failed       = true
      + allowed_registries = [
          + "aquacsacr.azurecr.io",
          + "registry.access.redhat.com",
        ]
    }

Plan: 6 to add, 0 to change, 0 to delete.
```

---

### Part 4: Show Policy in Aqua UI (2 min)

**Switch to Aqua UI:**
1. Navigate to **Policies** → **Image Assurance**
2. Show `prod-golden-image-enforcement` policy
3. Point out:
   - Application Scopes (prod-namespace)
   - Allowed Registries (4 approved)
   - Block Failed = Yes

**Script:**
> "This policy in the UI was created entirely by Terraform. If I need to add a new registry, I update the .tf file, commit to Git, run terraform apply, and it's deployed. No manual UI changes needed."

---

## 🔧 Detailed Policy Breakdown

### Policy 1: Golden Image Enforcement (⭐ Key Policy)

**File:** `golden-image-enforcement.tf`

**Purpose:** Blocks any container image not from approved registries at Kubernetes admission time

**Key Features:**
```hcl
resource "aquasec_image_assurance_policy" "prod_golden_image_enforcement" {
  name = "prod-golden-image-enforcement"

  # Only applies to production namespace
  application_scopes = ["prod-namespace"]

  # Approved golden image registries
  allowed_registries = {
    allowed_registries = [
      "aquacsacr.azurecr.io",        # Azure ACR - Our golden images
      "registry.access.redhat.com",   # Red Hat UBI (FIPS validated)
      "registry.customer.com",        # Customer's internal registry
      "ironbank.dso.mil"             # DoD Iron Bank
    ]
  }

  # CRITICAL: Block at admission (not just warn)
  block_failed = true

  # Fail if ANY control fails
  fail_cicd = true
}
```

**Demo Command:**
```bash
cat policies/golden-image-enforcement.tf
```

**Talking Points:**
- "This is the **primary enforcement mechanism** for our FIPS demo"
- "Uses Aqua's **Image Assurance** which evaluates at admission time via webhook"
- "Four approved registries - everything else is blocked"
- "Application scope ensures this only affects production workloads"

---

### Policy 2: FIPS Image Assurance (Pipeline Gate)

**File:** `fips-image-assurance-policy.tf`

**Purpose:** Validates images during CI/CD pipeline scan - blocks promotion if fails

**Key Controls:**
```hcl
resource "aquasec_image_assurance_policy" "fips_140_3_image_compliance" {
  name = "fips-140-3-image-compliance"

  # CVE Controls
  cvss_severity_enabled = true
  cvss_severity         = "high"
  maximum_score         = 7.0

  # Malware Detection
  malware = true

  # CIS Docker Benchmark
  docker_cis_enabled = true

  # Trusted Base Images
  trusted_base_images {
    enabled = true
    registry = "registry.access.redhat.com/ubi9"
  }

  # Custom REGO for CBOM validation
  custom_checks = [
    {
      script_id   = "fips-compliance-cdx16"
      description = "CBOM FIPS 140-3 crypto validation"
      author      = "Security Team"
      engine      = "rego"
      snippet     = file("${path.module}/fips-compliance-cdx16.rego")
    }
  ]

  block_failed = true
}
```

**Demo Command:**
```bash
cat policies/fips-image-assurance-policy.tf | grep -A 5 "cvss_severity\|malware\|docker_cis"
```

**Talking Points:**
- "This runs during the **pipeline** - Aqua Scanner evaluates the image"
- "CVSS > 7.0 blocks the build - no high/critical vulns allowed"
- "Malware detection ensures no crypto miners or trojans"
- "CIS Docker Benchmark validates secure image construction"

---

### Policy 3: Kubernetes Assurance (Workload Compliance)

**File:** `fips-kubernetes-policy.tf`

**Purpose:** Validates Kubernetes workload configuration and security contexts

**OOTB Controls:**
```hcl
resource "aquasec_function_runtime_policy" "fips_140_3_kubernetes_compliance" {
  name = "fips-140-3-kubernetes-compliance"

  application_scopes = ["prod-namespace"]

  # CPU/Memory Controls
  limit_container_priviliges = [
    {
      enabled                = true
      prevent_low_port_access = true
      prevent_root_user      = true  # ← PSS requirement
      block_privileged_containers = true
    }
  ]

  # Resource Limits Required
  kubernetes_controls = {
    enable_resource_limits = true
    enable_cpu_limits     = true
    enable_memory_limits  = true
  }

  # Custom REGO: Pod Security Standards Restricted
  custom_checks = [
    {
      script_id   = "PSSRestricted"
      description = "Validates PSS restricted mode compliance"
      engine      = "rego"
      snippet     = file("${path.module}/check_pss_restricted.rego")
    }
  ]
}
```

**Demo Command:**
```bash
grep -A 3 "prevent_root_user\|enable_resource_limits" policies/fips-kubernetes-policy.tf
```

**Talking Points:**
- "These controls validate the **Kubernetes manifests** themselves"
- "`prevent_root_user = true` enforces PSS restricted requirement"
- "Resource limits required prevents resource exhaustion attacks"
- "Custom REGO validates complete PSS restricted compliance"

---

### Policy 4: Container Runtime Policy (Behavioral Monitoring)

**File:** `fips-runtime-policy.tf`

**Purpose:** Monitors running containers for suspicious behavior

**Key Controls:**
```hcl
resource "aquasec_container_runtime_policy" "fips_140_3_runtime_compliance" {
  name = "fips-140-3-runtime-compliance"

  application_scopes = ["prod-namespace"]

  # Process Monitoring
  executable_blacklist {
    enabled = true
    executables = [
      "nc",      # Netcat - often used in attacks
      "nmap",    # Port scanning
      "tcpdump", # Packet capture
      "curl",    # Arbitrary downloads
      "wget"     # Arbitrary downloads
    ]
  }

  # File System Monitoring
  file_integrity_monitoring {
    enabled            = true
    monitored_paths    = ["/etc", "/usr/bin", "/usr/sbin"]
    exceptional_paths  = ["/tmp"]
  }

  # Network Monitoring
  limit_network_access {
    enabled = true
    block_outbound_connections = false  # Alert only
  }

  # Drift Prevention
  drift_prevention {
    enabled           = true
    exec_lockdown     = true  # Only allow pre-approved executables
  }
}
```

**Demo Command:**
```bash
grep -A 5 "executable_blacklist\|drift_prevention" policies/fips-runtime-policy.tf
```

**Talking Points:**
- "Once the container is running, this policy **watches its behavior**"
- "Executable blacklist prevents tools like netcat and nmap"
- "Drift prevention means **only the binaries in the image** can run"
- "If a compromised container tries to download tools, it's blocked"

---

## 💻 Complete Demo Commands

### Setup (Pre-Demo)
```bash
# Navigate to policies directory
cd /Users/home/Developer/CBOM/policies

# Ensure Terraform is installed
terraform version

# Initialize (if not done)
terraform init
```

### Demo Script

**1. Show Policy Structure**
```bash
echo "📋 FIPS 140-3 Policies (Terraform)"
echo "=================================="
ls -lh *.tf | awk '{print $9, "-", $5}'
echo ""
```

**2. Show Golden Image Policy**
```bash
echo "⭐ Golden Image Registry Enforcement"
echo "====================================="
cat golden-image-enforcement.tf
echo ""
read -p "Press Enter to continue..."
```

**3. Show FIPS Image Policy Controls**
```bash
echo "🔍 FIPS Image Assurance Controls"
echo "================================"
grep -E "cvss_severity|malware|docker_cis|trusted_base" fips-image-assurance-policy.tf
echo ""
read -p "Press Enter to continue..."
```

**4. Show Kubernetes Policy**
```bash
echo "☸️  Kubernetes Workload Compliance"
echo "=================================="
grep -E "prevent_root_user|enable_resource_limits|enable_cpu_limits" fips-kubernetes-policy.tf
echo ""
read -p "Press Enter to continue..."
```

**5. Show Runtime Policy**
```bash
echo "🏃 Runtime Behavioral Monitoring"
echo "==============================="
grep -A 8 "executable_blacklist" fips-runtime-policy.tf
echo ""
read -p "Press Enter to continue..."
```

**6. Show REGO Policies**
```bash
echo "📜 Custom REGO Policies"
echo "======================"
ls -lh *.rego
echo ""
echo "CBOM Validation:"
head -20 fips-compliance-cdx16.rego
echo ""
read -p "Press Enter to continue..."
```

**7. Show Terraform Plan (Dry Run)**
```bash
echo "🔧 Terraform Plan (What Would Be Deployed)"
echo "=========================================="
terraform plan -var-file=terraform.tfvars 2>&1 | head -50
echo ""
echo "Note: In production, we would run 'terraform apply' to deploy these policies to Aqua"
```

---

## 🎓 Terraform Benefits for Security Policies

### 1. Version Control & Audit Trail
```bash
# See policy history
git log --oneline policies/golden-image-enforcement.tf

# Compare versions
git diff HEAD~1 policies/golden-image-enforcement.tf
```

**Demo:** Show Git history of policy changes

---

### 2. Code Review Process
```bash
# Create feature branch for policy change
git checkout -b add-new-registry

# Edit policy
vim policies/golden-image-enforcement.tf

# Commit and create PR
git add policies/golden-image-enforcement.tf
git commit -m "feat: add gcr.io as approved registry"
git push origin add-new-registry
gh pr create --title "Add GCR to golden registries"
```

**Demo:** Show GitHub PR with policy diff

---

### 3. Testing Before Deployment
```bash
# Validate syntax
terraform validate

# Check formatting
terraform fmt -check

# Preview changes (safe)
terraform plan

# See what specific resources would change
terraform plan -out=tfplan
terraform show tfplan
```

**Demo:** Run `terraform plan` to show preview

---

### 4. Multi-Environment Consistency
```
environments/
├── dev/
│   └── terraform.tfvars     # Relaxed policies
├── staging/
│   └── terraform.tfvars     # Medium enforcement
└── prod/
    └── terraform.tfvars     # Strict FIPS policies
```

**Same policy code, different variable values**

---

### 5. Disaster Recovery
```bash
# Export current Aqua policies
terraform state pull > aqua-policies-backup.json

# Destroy and recreate (if needed)
terraform destroy
terraform apply

# All policies restored from code
```

---

## 📊 Policy Comparison: UI vs Terraform

| Feature | Manual UI | Terraform (IaC) |
|---------|-----------|-----------------|
| **Deployment** | Click through 20+ screens | `terraform apply` |
| **Consistency** | Human error prone | Guaranteed identical |
| **Audit Trail** | Aqua logs only | Git history + Aqua logs |
| **Testing** | Prod = test environment | Validate before deploy |
| **Recovery** | Manual rebuild | `terraform apply` |
| **Documentation** | Separate wiki | Self-documenting code |
| **Multi-Env** | Copy/paste errors | DRY with variables |
| **Review Process** | Email screenshots | GitHub PR workflow |

---

## 🎯 Customer Objections & Responses

### "We don't have Terraform skills on our team"

**Response:**
- HCL is human-readable (show example)
- Start with our pre-built policies
- Gradual adoption (manage 1 policy, then expand)
- Training available

### "What if Terraform state gets corrupted?"

**Response:**
- State stored in remote backend (S3, Azure Storage)
- State locking prevents conflicts
- State backup/versioning enabled
- Can import existing resources

### "Does this work with our GitOps workflow?"

**Response:**
- Yes! Terraform integrates with ArgoCD, Flux
- Policies deployed via CI/CD pipeline
- PR-based approval process
- Automatic rollback on failure

---

## 📁 Demo File Reference

```bash
# All policy files
policies/
├── golden-image-enforcement.tf           # ⭐ KEY POLICY
├── fips-image-assurance-policy.tf
├── fips-kubernetes-policy.tf
├── fips-runtime-policy.tf
├── CIS.tf
├── check_pss_restricted.rego
├── fips-compliance-cdx16.rego
└── fips-compliance-image-assurance.rego

# Terraform configuration
├── variables.tf                          # (Not in repo - credentials)
├── terraform.tfvars.example
└── .terraform.lock.hcl
```

---

## 🚀 Quick Demo Script (3 minutes)

```bash
#!/bin/bash
# Quick Terraform Policies Demo

cd /Users/home/Developer/CBOM/policies

echo "🎯 FIPS 140-3 Policies-as-Code Demo"
echo "==================================="
echo ""

echo "📦 Policy Files (Terraform HCL):"
ls -lh *.tf | awk '{print "  ", $9}'
echo ""

echo "⭐ Golden Image Enforcement Policy:"
grep -A 10 "resource \"aquasec_image_assurance_policy\"" golden-image-enforcement.tf | head -15
echo ""

echo "🔧 Deployment Process:"
echo "  1. terraform init   # Initialize provider"
echo "  2. terraform plan   # Preview changes"
echo "  3. terraform apply  # Deploy to Aqua"
echo ""

echo "✅ Result: All policies deployed to Aqua with scopes and enforcement rules"
echo ""

echo "📊 Benefits:"
echo "  ✅ Version controlled (Git)"
echo "  ✅ Code reviewed (PRs)"
echo "  ✅ Tested before deployment"
echo "  ✅ Identical across environments"
echo "  ✅ Self-documenting"
echo ""
```

---

## 📚 Additional Resources

- **Terraform Aqua Provider Docs:** https://registry.terraform.io/providers/aquasecurity/aquasec/latest/docs
- **Policy Files:** `/Users/home/Developer/CBOM/policies/`
- **Demo Commands:** This document
- **Live Demo:** `LIVE-DEMO-SCRIPT.md`

---

**Last Updated:** October 6, 2025
**Demo Duration:** 5-7 minutes (full), 3 minutes (quick)
**Audience:** Infrastructure/DevOps teams, Security architects, Compliance officers
