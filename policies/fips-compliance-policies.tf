# ==================================
# CORRECTED FIPS 140-3 Compliance Policies
# ==================================
# Validated against actual Aqua imported policies:
# - CIS.tf (Runtime baseline)
# - dora_ia.tf (Image assurance baseline)
# - dora_k8.tf (Kubernetes controls baseline)
#
# All structures and AVD IDs verified against production Aqua config

# ==================================
# Image Assurance Policy for FIPS 140-3
# ==================================
resource "aquasec_image_assurance_policy" "fips_image_compliance" {
  name               = "fips-140-2-image-compliance"
  description        = "FIPS 140-3 cryptographic compliance for secure manufacturing systems"
  application_scopes = ["Global"]
  enforce            = true
  enabled            = true

  # === FIPS Level 1: Basic Cryptographic Requirements ===
  trusted_base_images_enabled = true

  # Block non-compliant images
  block_failed = true
  fail_cicd    = true

  # === FIPS Level 2: Cryptographic Package Control ===
  packages_black_list_enabled = true
  packages_white_list_enabled = true

  # === CMVP Validation Requirements ===
  scan_sensitive_data = true
  disallow_malware    = true

  # Licensing compliance for FIPS modules
  blacklisted_licenses_enabled = false
  whitelisted_licenses_enabled = true
  whitelisted_licenses = [
    "OpenSSL",
    "BSD-3-Clause",
    "MIT",
    "Apache-2.0",
    "GPL-2.0-with-linking-exception"
  ]

  # === Security Level 4: Tamper Evidence/Response ===
  docker_cis_enabled = true
  linux_cis_enabled  = true

  # Enhanced scanning for crypto vulnerabilities
  maximum_score_enabled = true
  maximum_score         = 5
  cvss_severity_enabled = true
  cvss_severity         = "high"

  scope {
    expression = "v1"
    variables {
      attribute = "image.name"
      value     = "*"
    }
  }
}

# ==================================
# Runtime Policy for FIPS 140-3 (CORRECTED)
# ==================================
resource "aquasec_container_runtime_policy" "fips_runtime_compliance" {
  name               = "fips-140-2-runtime-compliance"
  description        = "FIPS 140-3 runtime controls for cryptographic module protection"
  application_scopes = ["Global"]
  enabled            = true
  enforce            = true

  # === Physical Security: Access Control (Top-Level) ===
  block_access_host_network = true
  block_use_pid_namespace   = true
  block_use_ipc_namespace   = true
  block_use_uts_namespace   = true
  no_new_privileges         = true

  # === Container Privilege Controls (CORRECTED STRUCTURE) ===
  limit_container_privileges {
    enabled                  = true
    privileged               = true # Blocks privileged containers
    prevent_root_user        = true # Blocks root user
    prevent_low_port_binding = true
    block_add_capabilities   = false
    netmode                  = true
    pidmode                  = true
    ipcmode                  = true
    use_host_user            = false
    usermode                 = true
    utsmode                  = true
  }

  # === Self-Tests: File Integrity Monitoring ===
  file_integrity_monitoring {
    enabled = true
    monitored_files = [
      "/proc/sys/crypto/fips_enabled",
      "/etc/system-fips",
      "/usr/lib64/openssl/engines/fips.so",
      "/etc/crypto-policies/back-ends/opensslcnf.config",
      "/etc/ssl/fips/*",
      "/usr/lib/fipscheck/*"
    ]
    monitored_files_modify = true
    monitored_files_delete = true
    monitored_files_create = true
  }

  # === Tamper Detection: Package Protection ===
  package_block {
    enabled = true
    packages_black_list = [
      "openssl-libs",
      "python-crypto",
      "openssl-devel"
    ]
  }

  # === Executable Control: Crypto Binary Protection ===
  executable_blacklist {
    enabled = true
    executables = [
      "openssl-non-fips",
      "ssh-keygen-non-fips",
      "crypto-test-tools"
    ]
  }

  # === Volume Security: Crypto Asset Protection ===
  restricted_volumes {
    enabled = true
    volumes = [
      "/",
      "/boot",
      "/dev",
      "/etc",
      "/lib",
      "/proc",
      "/sys",
      "/usr",
      "/var/lib/docker",
      "/etc/ssl",
      "/etc/crypto-policies",
      "/usr/lib/fipscheck"
    ]
  }

  # === Audit Controls: Cryptographic Operations ===
  auditing {
    enabled                       = true
    audit_all_processes           = true
    audit_process_cmdline         = true
    audit_user_account_management = true
    audit_success_login           = true
    audit_failed_login            = true
  }

  # === Network Security: Crypto Communication ===
  enable_ip_reputation        = true
  enable_port_scan_protection = true
  enable_crypto_mining_dns    = true

  # === System Integrity: Tamper Evidence ===
  system_integrity_protection {
    enabled                     = true
    audit_systemtime_change     = true
    monitor_audit_log_integrity = true
  }

  scope_variables {
    attribute = "container.name"
    value     = "*"
  }
}

# ==================================
# Kubernetes Assurance Policy for FIPS 140-3 (CORRECTED)
# ==================================
resource "aquasec_kubernetes_assurance_policy" "fips_k8s_compliance" {
  name               = "fips-140-2-kubernetes-compliance"
  description        = "Kubernetes controls for FIPS 140-3 cryptographic workloads"
  application_scopes = ["Global"]
  enforce            = true
  enabled            = true

  # === Key Management: Secret Protection ===
  kubernetes_controls {
    avd_id      = "AVD-KSV-0109"
    description = "Storing secrets in configMaps is unsafe"
    enabled     = true
    kind        = "configmap"
    name        = "ConfigMap with secrets"
    ootb        = true
    script_id   = 96
    severity    = "critical"
  }

  kubernetes_controls {
    avd_id      = "AVD-KSV-01010"
    description = "Storing sensitive content such as usernames and email addresses in configMaps is unsafe"
    enabled     = true
    kind        = "configmap"
    name        = "ConfigMap with sensitive content"
    ootb        = true
    script_id   = 97
    severity    = "medium"
  }

  kubernetes_controls {
    avd_id      = "AVD-KSV-0041"
    description = "Viewing secrets at the cluster-scope is akin to cluster-admin"
    enabled     = true
    kind        = "roleandrolebinding"
    name        = "Manage secrets"
    ootb        = true
    script_id   = 114
    severity    = "critical"
  }

  # === Role-Based Authentication: Access Control ===
  kubernetes_controls {
    avd_id      = "AVD-KSV-0012"
    description = "Force the running image to run as a non-root user to ensure least privileges"
    enabled     = true
    kind        = "workload"
    name        = "Runs as root user"
    ootb        = true
    script_id   = 121
    severity    = "medium"
  }

  kubernetes_controls {
    avd_id      = "AVD-KSV-0017"
    description = "Privileged containers share namespaces with the host system and do not offer any security"
    enabled     = true
    kind        = "workload"
    name        = "Privileged"
    ootb        = true
    script_id   = 104
    severity    = "high"
  }

  # === Operational Environment: Network Security ===
  kubernetes_controls {
    avd_id      = "AVD-KSV-0008"
    description = "Sharing the host's IPC namespace allows container processes to communicate with processes on the host"
    enabled     = true
    kind        = "workload"
    name        = "Access to host IPC namespace"
    ootb        = true
    script_id   = 89
    severity    = "high"
  }

  kubernetes_controls {
    avd_id      = "AVD-KSV-0009"
    description = "Sharing the host's network namespace permits processes in the pod to communicate with processes bound to the host's loopback adapter"
    enabled     = true
    kind        = "workload"
    name        = "Access to host network"
    ootb        = true
    script_id   = 91
    severity    = "critical"
  }

  # === Physical Security: Volume Protection ===
  kubernetes_controls {
    avd_id      = "AVD-KSV-0023"
    description = "According to pod security standard 'HostPath Volumes', HostPath volumes must be forbidden"
    enabled     = true
    kind        = "workload"
    name        = "hostPath volumes mounted"
    ootb        = true
    script_id   = 103
    severity    = "high"
  }

  kubernetes_controls {
    avd_id      = "AVD-KSV-0014"
    description = "An immutable root file system prevents applications from writing to their local disk"
    enabled     = true
    kind        = "workload"
    name        = "Root file system is not read-only"
    ootb        = true
    script_id   = 102
    severity    = "high"
  }

  # === Tamper Evidence: Resource Controls ===
  kubernetes_controls {
    avd_id      = "AVD-KSV-0011"
    description = "Enforcing CPU limits prevents DoS via resource exhaustion"
    enabled     = true
    kind        = "workload"
    name        = "CPU not limited"
    ootb        = true
    script_id   = 83
    severity    = "medium"
  }

  kubernetes_controls {
    avd_id      = "AVD-KSV-0018"
    description = "Enforcing memory limits prevents DoS via resource exhaustion"
    enabled     = true
    kind        = "workload"
    name        = "Memory not limited"
    ootb        = true
    script_id   = 117
    severity    = "medium"
  }

  # === Namespace Isolation: Crypto Workload Separation ===
  required_labels_enabled = true
  required_labels = [
    {
      key   = "fips.compliance"
      value = "required"
    },
    {
      key   = "crypto.level"
      value = "fips-140-2"
    },
    {
      key   = "security.clearance"
      value = "controlled"
    }
  ]

  scope {
    expression = "v1"
    variables {
      attribute = "kubernetes.namespace"
      value     = "*fips*"
    }
  }
}

# ==================================
# Aqua-CBOM Integration Examples
# ==================================
locals {
  cbom_integration_examples = [
    {
      name        = "Quantum-Safe Cryptography Assessment"
      description = "Scan for quantum-vulnerable cryptographic algorithms"
      command     = "aqua-cbom -mode file -dir /tmp/image | jq -r '.components[] | select(.crypto.quantumSafe == false) | .crypto.algorithm' | wc -l | test $(cat) -eq 0"
    },
    {
      name        = "CMVP Module Validation"
      description = "Verify cryptographic modules have CMVP validation"
      command     = "aqua-cbom -mode file -dir /tmp/image | jq -r '.components[] | select(.crypto.cmvpValidated == false) | .name' | wc -l | test $(cat) -eq 0"
    },
    {
      name        = "Cryptographic Asset Inventory"
      description = "Generate complete CBOM for compliance reporting"
      command     = "aqua-cbom -mode file -dir /tmp/image -output-cbom > /tmp/compliance-cbom.json && test -s /tmp/compliance-cbom.json"
    }
  ]
}