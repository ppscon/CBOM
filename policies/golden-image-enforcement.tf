# ==================================
# Golden Image Repository Enforcement
# ==================================
# Enterprise pattern: Only allow vetted, FIPS-compliant images from
# the Golden Image registry in production namespace
#
# Architecture:
# 1. CI/CD pipeline → CBOM crypto scan → Aqua scan
# 2. Approved images → Promoted to Golden Registry
# 3. Aqua admission control → Only allows Golden Registry in prod namespace
# 4. PSS restricted mode → Enforces security context

# ==================================
# Application Scope: Production Namespace
# ==================================
resource "aquasec_application_scope" "prod_namespace" {
  name        = "prod-namespace-scope"
  description = "Production namespace with PSS restricted mode - requires golden images"

  categories {
    # Artifacts category for Image Assurance policies
    artifacts {
      image {
        expression = "v1"
        variables {
          attribute = "image.name"
          value     = "*"
        }
      }
    }

    # Workloads category for runtime enforcement
    workloads {
      kubernetes {
        expression = "v1"
        variables {
          attribute = "kubernetes.namespace"
          value     = "prod"
        }
      }
    }
  }
}

# ==================================
# Image Assurance Policy: Golden Image Registry Only
# ==================================
resource "aquasec_image_assurance_policy" "golden_image_enforcement" {
  name               = "prod-golden-image-enforcement"
  description        = "Production namespace: Only allow images from vetted Golden Image registry"
  application_scopes = [aquasec_application_scope.prod_namespace.name]
  enabled            = true
  enforce            = true

  # Block at admission time
  block_failed     = true
  fail_cicd        = true
  audit_on_failure = true

  # ========================================
  # GOLDEN IMAGE REGISTRY WHITELIST
  # ========================================
  # Only allow images from approved registries
  # These registries contain FIPS-validated images

  # Approved Base Image control (shows in UI)
  allowed_registries {
    allowed_registries = [
      "registry.access.redhat.com",  # Red Hat UBI FIPS images
      "registry.customer.com",        # Customer's golden image registry
      "ironbank.dso.mil",            # DoD Iron Bank (FIPS-approved)
      "aquacsacr.azurecr.io"         # Azure ACR - Demo golden images
    ]
  }

  # Enable trusted base images control
  trusted_base_images_enabled = true

  # ========================================
  # SECURITY CONTROLS
  # ========================================

  # Malware and sensitive data scanning
  scan_sensitive_data = true
  disallow_malware    = true

  # CVE and vulnerability controls (relaxed for demo)
  cvss_severity_enabled = true
  cvss_severity         = "critical"  # Only block critical (was "high")
  maximum_score_enabled = true
  maximum_score         = 9.0  # Raised threshold for demo (was 7.0)

  # CIS compliance benchmarks
  docker_cis_enabled = true
  linux_cis_enabled  = true

  # Only allow non-root users
  only_none_root_users = true

  # Scope: All images (filtering done at application scope level)
  scope {
    expression = "v1"
    variables {
      attribute = "image.name"
      value     = "*"
    }
  }
}

# ==================================
# Outputs
# ==================================
output "prod_scope_name" {
  value       = aquasec_application_scope.prod_namespace.name
  description = "Production namespace application scope"
}

output "golden_image_policy_name" {
  value       = aquasec_image_assurance_policy.golden_image_enforcement.name
  description = "Golden image enforcement policy name"
}

output "approved_registries" {
  value       = aquasec_image_assurance_policy.golden_image_enforcement.registries
  description = "Approved golden image registries for production"
}
