# Import blocks for demo - uncomment as needed

# Runtime policy - CIS exists by default in Aqua
# import {
#   to = aquasec_container_runtime_policy.CIS
#   id = "CIS"
# }

# Kubernetes assurance policy - create dora_k8 in Aqua first
# import {
#   to = aquasec_kubernetes_assurance_policy.dora_k8
#   id = "dora_k8"
# }

# Image assurance policy - create dora_ia in Aqua first
import {
  to = aquasec_image_assurance_policy.dora_ia
  id = "dora_ia"
}
