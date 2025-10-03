# FIPS Cryptographic Compliance REGO Policy - Demo Guide

## Overview

This guide provides an **exact narration script** for demoing the custom FIPS 140-3 Cryptographic Compliance REGO policy in Aqua Platform.

---

## Policy Details

**Name**: `FIPSCryptographicCompliance`
**File**: `policies/aqua-fips-crypto-compliance.rego`
**Type**: Kubernetes Security Check
**Severity**: CRITICAL
**Location**: Aqua Platform → Policies → Assurance Policies → Compliance Checks

---

## Demo Narration Script

### Part 1: The Challenge (30 seconds)

**"Let me show you a real-world compliance challenge our customers face with FIPS 140-3.**

**FIPS 140-3 is mandatory for any system processing sensitive government data - think defense contractors, healthcare systems, financial institutions. The deadline is September 2026 - all FIPS 140-2 certificates become historical.**

**The problem? Most organizations are using base images with outdated cryptographic libraries - old OpenSSL versions, deprecated crypto packages. These fail FIPS compliance audits and create serious security gaps."**

---

### Part 2: The Solution - Custom REGO Policy (1 minute)

**"Here's how Aqua solves this with a custom REGO policy I wrote specifically for FIPS cryptographic compliance."**

#### Show Policy in Aqua UI

Navigate to: **Policies → Assurance Policies → Compliance Checks → FIPSCryptographicCompliance**

**"This is a custom Kubernetes Security Check - one of hundreds we ship out-of-the-box, but this one is tailored for FIPS 140-3 requirements."**

**Point to the policy details:**

- **"Severity: CRITICAL"** - This is a blocking policy. If it fails, deployments are rejected.
- **"Type: Workloads"** - Applies to Deployments, StatefulSets, DaemonSets, Jobs, Pods
- **"Description: Workloads with FIPS compliance labels must use FIPS certified base images"** - This is label-driven enforcement

---

### Part 3: How It Works - The REGO Logic (1.5 minutes)

**Click on the policy to show the REGO code.**

**"Let me walk you through the logic - this is Open Policy Agent (OPA) REGO, the industry standard for policy-as-code."**

#### Line-by-line narration:

**1. Package Declaration (Line 1)**
```rego
package appshield.kubernetes.FIPSCryptoCompliance
```
**"This policy lives in Aqua's `appshield.kubernetes` namespace, making it part of our Kubernetes security framework."**

---

**2. Metadata Block (Lines 5-14)**
```rego
__rego_metadata__ := {
    "id": "FIPSCryptoCompliance",
    "severity": "CRITICAL",
    "type": "Kubernetes Security Check",
    ...
}
```
**"The metadata defines this as a CRITICAL severity policy. When this fires, it's a deployment-blocking event."**

---

**3. Selector (Lines 16-23)**
```rego
__rego_input__ := {
    "selector": [
        {"type": "kubernetes", "group": "apps", "version": "v1", "kind": "deployment"},
        {"type": "kubernetes", "group": "apps", "version": "v1", "kind": "statefulset"},
        ...
    ]
}
```
**"The selector tells Aqua which Kubernetes resources this policy evaluates - Deployments, StatefulSets, DaemonSets. Basically, anything that runs a container."**

---

**4. FIPS-Approved Image List (Line 25)**
```rego
fipsApprovedPrefixes := [
    "registry.access.redhat.com/ubi8",
    "registry.access.redhat.com/ubi9",
    "ubuntu/fips",
    "ironbank"
]
```
**"Here's the whitelist - the only base images allowed for FIPS workloads. Red Hat Universal Base Image 8 and 9 are FIPS-certified. Ubuntu FIPS images. And Ironbank, which is the DoD's hardened container registry."**

**"Notice what's NOT on this list - no `ubuntu:latest`, no `alpine`, no `node:16`. Those don't have FIPS-validated cryptographic modules."**

---

**5. Label Check (Lines 27-29)**
```rego
hasFIPSLabel {
    kubernetes.metadata.labels["fips.compliance"] == "required"
}
```
**"This is the trigger. The policy only activates if the deployment has the label `fips.compliance: required`. This gives teams flexibility - not every workload needs FIPS compliance, only the ones handling sensitive data."**

---

**6. Image Validation (Lines 31-33)**
```rego
isFIPSApprovedImage(image) {
    startswith(image, fipsApprovedPrefixes[_])
}
```
**"Simple check - does the container image start with one of our approved prefixes? If not, it's rejected."**

---

**7. Violation Detection (Lines 35-39)**
```rego
violatesFIPSCompliance {
    hasFIPSLabel
    container := kubernetes.containers[_]
    not isFIPSApprovedImage(container.image)
}
```
**"Here's the logic: IF the deployment has a FIPS label, AND any container uses a non-approved image, THEN we have a violation."**

---

**8. Deny Rule (Lines 41-51)**
```rego
deny[res] {
    violatesFIPSCompliance
    msg := kubernetes.format(sprintf("%s %s in namespace %s requires FIPS certified base images",
        [kubernetes.kind, kubernetes.name, kubernetes.namespace]))
    res := {
        "msg": msg,
        "id": __rego_metadata__.id,
        "severity": __rego_metadata__.severity,
        ...
    }
}
```
**"When we detect a violation, we return a structured denial. The deployment is blocked, and we provide a clear error message: 'Deployment XYZ in namespace ABC requires FIPS certified base images.'"**

---

### Part 4: Real-World Example (2 minutes)

**"Let me show you this in action."**

#### Scenario 1: Non-FIPS Deployment (PASS)

**"First, a normal deployment without FIPS requirements:"**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: development
  labels:
    app: web
    # No FIPS label - policy doesn't apply
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:latest  # Non-FIPS image, but that's OK
```

**"This deploys successfully. Why? No `fips.compliance: required` label. The policy doesn't even run. Teams have flexibility for non-sensitive workloads."**

---

#### Scenario 2: FIPS Deployment with Compliant Image (PASS)

**"Now, a FIPS-required deployment with the correct base image:"**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-processor
  namespace: production
  labels:
    app: payments
    fips.compliance: required  # FIPS enforcement enabled
spec:
  template:
    spec:
      containers:
      - name: api
        image: registry.access.redhat.com/ubi8/ubi-minimal:latest  # ✅ FIPS-certified
```

**"This deploys successfully. Why? The label triggers the policy, but the image is Red Hat UBI 8 - which is on our approved list. FIPS compliance verified."**

---

#### Scenario 3: FIPS Deployment with Non-Compliant Image (BLOCKED)

**"Now the important one - what happens when someone tries to deploy a non-compliant image?"**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-processor
  namespace: production
  labels:
    app: payments
    fips.compliance: required  # FIPS enforcement enabled
spec:
  template:
    spec:
      containers:
      - name: api
        image: node:16-alpine  # ❌ NOT FIPS-certified
```

**"This deployment is BLOCKED by Aqua Admission Controller."**

**Show error message:**
```
❌ FIPS Cryptographic Compliance Policy Violation

Deployment 'payment-processor' in namespace 'production' requires FIPS certified base images

Severity: CRITICAL
Policy: FIPSCryptoCompliance (AVDFIPS001)

Recommendation: Use FIPS certified base images such as:
  - registry.access.redhat.com/ubi8
  - registry.access.redhat.com/ubi9
  - ubuntu/fips
  - ironbank
```

**"The developer gets immediate feedback. They can't deploy this workload until they switch to a FIPS-certified base image. This prevents compliance violations before they reach production."**

---

### Part 5: Why This Matters - Business Impact (1 minute)

**"Let's talk about why this is critical for our customers:**

**1. Compliance Automation**
- **"Manual audits take weeks. This policy enforces compliance in milliseconds."**
- **"Every deployment is automatically validated - no human error, no exceptions."**

**2. Audit Trail**
- **"Aqua logs every policy evaluation. When auditors ask 'How do you ensure FIPS compliance?' - you show them this policy and the logs."**

**3. Developer Experience**
- **"Developers get clear, actionable feedback. Not just 'deployment failed' - but exactly what to fix and which images to use."**

**4. Defense-in-Depth**
- **"This is just one layer. We also have:"**
  - **Image Assurance** - Scans for vulnerable OpenSSL packages
  - **Runtime Protection** - Monitors crypto library file integrity
  - **CBOM Validation** - Deep algorithm analysis (MD5, weak RSA keys, etc.)

**"Four layers of crypto compliance enforcement - from build to runtime."**

---

### Part 6: Customization - Make It Yours (30 seconds)

**"And here's the best part - this policy is fully customizable:"**

**"Want to add your organization's internal registry?"**
```rego
fipsApprovedPrefixes := [
    "registry.access.redhat.com/ubi8",
    "registry.access.redhat.com/ubi9",
    "your-internal-registry.com/fips-images",  # Add your registry
    "ironbank"
]
```

**"Want to enforce different labels?"**
```rego
hasFIPSLabel {
    kubernetes.metadata.labels["security.level"] == "high"  # Custom label
}
```

**"Want to make it WARNING instead of BLOCKING?"**
```rego
__rego_metadata__ := {
    "severity": "HIGH",  # Changed from CRITICAL
    ...
}
```

**"This is policy-as-code. Version-controlled, testable, auditable."**

---

### Part 7: Integration with Full Pipeline (1 minute)

**"Let me show you how this fits into the complete FIPS 140-3 compliance pipeline:"**

**Show pipeline diagram or GitHub Actions workflow:**

```
┌─────────────────────────────────────────────────────────────┐
│           FIPS 140-3 Compliance Pipeline (Aqua)             │
├─────────────────────────────────────────────────────────────┤
│  Stage 1: Build Application Image                           │
│    └─> ghcr.io/yourorg/app:abc123                          │
├─────────────────────────────────────────────────────────────┤
│  Stage 2: Aqua Image Assurance (FIRST GATE)                │
│    └─> CVE scan, malware detection, CIS benchmarks         │
│    └─> Package validation (checks OpenSSL versions)        │
│    └─> CRITICAL CVEs? → BLOCK                              │
├─────────────────────────────────────────────────────────────┤
│  Stage 3: CBOM Generation                                   │
│    └─> Cryptographic Bill of Materials                     │
│    └─> Detects: MD5, SHA-1, RSA-1024, weak algorithms     │
├─────────────────────────────────────────────────────────────┤
│  Stage 4: REGO Policy Evaluation (OPA CLI)                 │
│    └─> Validates CBOM against fips-compliance-cdx16.rego   │
│    └─> Deprecated algorithms? → BLOCK                      │
├─────────────────────────────────────────────────────────────┤
│  Stage 5: Push FIPS-Compliant Image                        │
│    └─> Tag: fips-140-3-compliant-abc123                   │
│    └─> Only if ALL gates pass                              │
├─────────────────────────────────────────────────────────────┤
│  Stage 6: Kubernetes Deployment ⭐ THIS POLICY              │
│    └─> Aqua Admission Controller                           │
│    └─> Evaluates FIPSCryptographicCompliance.rego         │
│    └─> Non-FIPS base image? → BLOCK                       │
└─────────────────────────────────────────────────────────────┘
```

**"This REGO policy runs at Stage 6 - the last gate before production. Even if an image passes the build pipeline, if someone tries to deploy it with a FIPS label but a non-compliant base image, Aqua blocks it."**

---

### Part 8: Comparison - Aqua vs. Manual Compliance (30 seconds)

**Show slide or verbal comparison:**

| Approach | Manual Process | Aqua Platform |
|----------|---------------|---------------|
| **Policy Creation** | Word documents, spreadsheets | REGO code (version-controlled) |
| **Enforcement** | Manual reviews, quarterly audits | Real-time, automated blocking |
| **Coverage** | Sample-based (5-10% of deployments) | 100% of deployments |
| **Audit Trail** | Email threads, meeting notes | Immutable logs, policy versions |
| **Time to Detect** | Weeks to months | Milliseconds |
| **Developer Feedback** | Post-deployment findings | Pre-deployment prevention |

**"With Aqua, you shift compliance left - catching issues at deployment time, not after they're in production."**

---

## Key Talking Points (Quick Reference)

Use these for Q&A or to emphasize during the demo:

✅ **"This is one of hundreds of policies Aqua provides out-of-the-box, but fully customizable for your org."**

✅ **"Label-driven enforcement - only applies to workloads that need FIPS compliance, giving teams flexibility."**

✅ **"CRITICAL severity means it's a blocking policy - deployments fail immediately with clear error messages."**

✅ **"Validates base images against FIPS-certified registries: Red Hat UBI, Ubuntu FIPS, DoD Ironbank."**

✅ **"Integrates with Kubernetes Admission Controller - enforcement happens before pods are scheduled."**

✅ **"Part of a defense-in-depth strategy: Image Assurance + CBOM validation + Runtime Protection + Admission Control."**

✅ **"Policy-as-code: version-controlled, testable, auditable - managed in Git alongside your infrastructure."**

✅ **"100% coverage - every deployment is validated automatically. No sampling, no human error."**

---

## Demo Environment Setup

### Prerequisites

1. **Aqua Platform** with Admission Controller enabled
2. **Kubernetes cluster** with Aqua enforcer deployed
3. **Policy imported** (`aqua-fips-crypto-compliance.rego`)
4. **Test deployments** ready:
   - `demo/non-fips-deployment.yaml` (no label, passes)
   - `demo/fips-compliant-deployment.yaml` (FIPS label + UBI image, passes)
   - `demo/fips-violation-deployment.yaml` (FIPS label + Alpine image, blocked)

### Test Deployments

**File: `demo/fips-violation-deployment.yaml`**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-api
  namespace: production
  labels:
    app: payments
    fips.compliance: required
spec:
  replicas: 1
  selector:
    matchLabels:
      app: payments
  template:
    metadata:
      labels:
        app: payments
    spec:
      containers:
      - name: api
        image: node:16-alpine  # Non-FIPS image
        ports:
        - containerPort: 3000
```

**Demo command:**
```bash
kubectl apply -f demo/fips-violation-deployment.yaml

# Expected output:
# Error from server: admission webhook "imageassurance.aquasec.com" denied the request:
# Deployment 'payment-api' in namespace 'production' requires FIPS certified base images
# Severity: CRITICAL
# Policy: FIPSCryptoCompliance (AVDFIPS001)
```

---

## Customer Objections & Responses

### "We already have image scanning. Why do we need this?"

**Response:**
**"Image scanning finds vulnerabilities in packages. This policy enforces compliance at deployment time. Even if an image passes the build pipeline, if someone manually deploys it with the wrong label or wrong base image, this policy catches it. It's the last line of defense before production."**

---

### "Can't we just document which images to use?"

**Response:**
**"Documentation doesn't scale. When you have 50 development teams deploying 500 microservices, you need automation. This policy enforces your documentation as code - it's impossible to bypass."**

---

### "What if we need to use a different base image temporarily?"

**Response:**
**"Two options: First, add it to the approved list - it's just one line of code. Second, remove the FIPS label from the deployment if it truly doesn't need FIPS compliance. The policy gives you flexibility while maintaining security."**

---

### "How do we handle exceptions?"

**Response:**
**"Exceptions are handled in code, not in ad-hoc approvals. If a team needs a specific registry, add it to `fipsApprovedPrefixes` via a Git pull request. That creates an audit trail - who requested it, when, why, who approved it. Much better than an email approval."**

---

## Follow-Up Resources

After the demo, provide:

1. **Policy file**: `policies/aqua-fips-crypto-compliance.rego`
2. **Setup guide**: `.github/AQUA-SETUP-GUIDE.md`
3. **Pipeline documentation**: `.github/workflows/README.md`
4. **FIPS architecture**: `docs/REGO Policy Narration for FIPS 140-3 Compliance.md`
5. **Demo comparison**: `.github/PIPELINE-COMPARISON.md` (Trivy vs Aqua)

---

## Success Criteria

After the demo, the customer should understand:

✅ How Aqua enforces FIPS 140-3 compliance using custom REGO policies
✅ How label-driven enforcement provides flexibility without sacrificing security
✅ How Admission Controller blocks non-compliant deployments in real-time
✅ How this integrates with the full pipeline (Image Assurance → CBOM → Deployment)
✅ How policy-as-code enables version control, auditability, and customization

---

## Next Steps After Demo

1. **Schedule POC**: Install Aqua in customer's dev/staging environment
2. **Import policy**: Upload `aqua-fips-crypto-compliance.rego` to customer's Aqua instance
3. **Configure Admission Controller**: Enable Kubernetes enforcement
4. **Test with customer's images**: Validate their base images against FIPS requirements
5. **Customize policy**: Adjust approved registries for customer's internal images
6. **Deploy Terraform policies**: Apply full FIPS compliance stack (Image + Runtime + Kubernetes)

---

**Last Updated**: 2025-10-03
**Policy Version**: v1.0.0
**Aqua Compatibility**: Tested on Aqua Platform 2022.4+
**Author**: Security Team
