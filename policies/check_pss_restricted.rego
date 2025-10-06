package appshield.kubernetes.PSSRestricted

import data.lib.kubernetes

default failPSSRestricted = false

__rego_metadata__ := {
     "id": "PSSRestricted",
    "title": "PSS Restricted Mode",
    "version": "1.0.0",
    "severity": "MEDIUM",
    "type": "K8sSecChk",
    "description": "Policy to enforce PSS.",
    "recommended_actions": "Enforce the PSS restricted mode."
}

__rego_input__ := {
    "combine": false,
    "selector": [
        {
            "type": "kubernetes",
            "group": "apps",
            "version": "v1",
            "kind": "deployment"
        }
    ]
}

check_pss_restricted(container) {
    securityContext := container.securityContext

    securityContext.runAsNonRoot == true
    securityContext.runAsUser >= 1000
    securityContext.allowPrivilegeEscalation == false
    capabilities := securityContext.capabilities
    capabilities.drop[_] == "ALL"
}

getNonCompliantContainers[container] {
    container := kubernetes.containers[_]
    not check_pss_restricted(container)
}

is_pss_restricted_label {
    labelKey := "pod-security.kubernetes.io/enforce"
    kubernetes.metadata.labels[labelKey] == "restricted"
    is_target_namespace
}

is_target_namespace {
    kubernetes.namespace == "infradev"
}

is_target_namespace {
    kubernetes.namespace == "prod"
}

failPSSRestricted {
    is_pss_restricted_label
    count(getNonCompliantContainers) > 0
}

deny[res] {
    failPSSRestricted

    msg := kubernetes.format(
        sprintf(
            "container %s of %s %s in %s namespace does not meet PSS restricted mode requirements",
            [getNonCompliantContainers[_].name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
        )
    )
    res := {
        "msg": msg,
        "id": __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type": __rego_metadata__.type,
      }
    }

