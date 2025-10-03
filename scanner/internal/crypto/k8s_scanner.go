package crypto

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sScanner handles Kubernetes-specific scanning operations
type K8sScanner struct {
	clientset *kubernetes.Clientset
	scanner   *Scanner
}

// NewK8sScanner creates a new Kubernetes scanner
func NewK8sScanner(scanner *Scanner) (*K8sScanner, error) {
	// Try in-cluster config first, then kubeconfig
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create Kubernetes config: %v", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	return &K8sScanner{
		clientset: clientset,
		scanner:   scanner,
	}, nil
}

// ScanKubernetesCluster scans a Kubernetes cluster for crypto vulnerabilities
func (k *K8sScanner) ScanKubernetesCluster(namespaces []string, secretScan, configMapScan, imageScan, networkPolicyScan, ingressScan, serviceMeshScan, deepCodeScan, includeKubeSystem bool) ([]Result, int) {
	var results []Result
	assetCount := 0

	// If no namespaces specified, get all accessible namespaces
	if len(namespaces) == 0 {
		discoveredNamespaces, err := k.discoverNamespaces(includeKubeSystem)
		if err != nil {
			if k.scanner.Verbose {
				fmt.Printf("Error discovering namespaces: %v\n", err)
			}
		} else {
			namespaces = discoveredNamespaces
		}
	}

	if k.scanner.Verbose {
		fmt.Printf("Scanning Kubernetes cluster across %d namespaces: %v\n", len(namespaces), namespaces)
	}

	// Scan secrets for crypto material
	if secretScan {
		secretResults, secretCount := k.scanSecrets(namespaces)
		results = append(results, secretResults...)
		assetCount += secretCount
	}

	// Scan ConfigMaps for crypto configurations
	if configMapScan {
		configMapResults, configMapCount := k.scanConfigMaps(namespaces)
		results = append(results, configMapResults...)
		assetCount += configMapCount
	}

	// Scan container images (if enabled)
	if imageScan {
		imageResults, imageCount := k.scanContainerImages(namespaces)
		results = append(results, imageResults...)
		assetCount += imageCount
	}

	// Additional resource scanning (placeholder for now)
	if networkPolicyScan {
		networkResults, networkCount := k.scanNetworkPolicies(namespaces)
		results = append(results, networkResults...)
		assetCount += networkCount
	}

	if ingressScan {
		ingressResults, ingressCount := k.scanIngresses(namespaces)
		results = append(results, ingressResults...)
		assetCount += ingressCount
	}

	if k.scanner.Verbose {
		fmt.Printf("Kubernetes scan completed. Analyzed %d assets across %d namespaces.\n", assetCount, len(namespaces))
	}

	return results, assetCount
}

// discoverNamespaces discovers all accessible namespaces
func (k *K8sScanner) discoverNamespaces(includeKubeSystem bool) ([]string, error) {
	namespaceList, err := k.clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var namespaces []string
	for _, ns := range namespaceList.Items {
		// Skip kube-system unless explicitly requested
		if !includeKubeSystem && (ns.Name == "kube-system" || ns.Name == "kube-public" || ns.Name == "kube-node-lease") {
			continue
		}
		namespaces = append(namespaces, ns.Name)
	}

	return namespaces, nil
}

// scanSecrets scans Kubernetes secrets for crypto material
func (k *K8sScanner) scanSecrets(namespaces []string) ([]Result, int) {
	var results []Result
	assetCount := 0

	for _, namespace := range namespaces {
		if k.scanner.Verbose {
			fmt.Printf("Scanning secrets in namespace: %s\n", namespace)
		}

		secretList, err := k.clientset.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			if k.scanner.Verbose {
				fmt.Printf("Error listing secrets in namespace %s: %v\n", namespace, err)
			}
			continue
		}

		for _, secret := range secretList.Items {
			assetCount++
			secretResults := k.analyzeSecret(secret.Name, namespace, secret.Data, string(secret.Type))
			results = append(results, secretResults...)
		}
	}

	return results, assetCount
}

// analyzeSecret analyzes a Kubernetes secret for crypto vulnerabilities
func (k *K8sScanner) analyzeSecret(secretName, namespace string, data map[string][]byte, secretType string) []Result {
	var results []Result

	for key, value := range data {
		// Decode base64 content if needed
		content := string(value)
		
		// Check if content is base64 encoded (common for TLS secrets)
		if decoded, err := base64.StdEncoding.DecodeString(content); err == nil {
			content = string(decoded)
		}

		// Analyze content for crypto patterns
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			for _, rule := range k.scanner.Rules {
				if match, _ := regexp.MatchString(rule.Pattern, line); match {
					results = append(results, Result{
						File:              fmt.Sprintf("secret/%s/%s (%s)", secretName, key, namespace),
						Algorithm:         rule.AlgorithmName,
						Type:              rule.AlgorithmType,
						Line:              lineNum + 1,
						Method:            "Kubernetes Secret Analysis",
						Risk:              rule.RiskLevel,
						VulnerabilityType: rule.VulnerabilityType,
						Description:       fmt.Sprintf("Secret contains %s: %s", rule.AlgorithmName, rule.Description),
						Recommendation:    rule.Recommendation,
					})
				}
			}
		}

		// Special handling for TLS secrets
		if secretType == "kubernetes.io/tls" || strings.Contains(key, "tls") || strings.Contains(key, "cert") {
			if strings.Contains(content, "BEGIN CERTIFICATE") || strings.Contains(content, "BEGIN RSA PRIVATE KEY") {
				// Analyze certificate/key content
				certResults := k.analyzeTLSMaterial(secretName, namespace, key, content)
				results = append(results, certResults...)
			}
		}
	}

	return results
}

// analyzeTLSMaterial analyzes TLS certificates and keys
func (k *K8sScanner) analyzeTLSMaterial(secretName, namespace, key, content string) []Result {
	var results []Result

	// Check for RSA keys/certificates
	if strings.Contains(content, "RSA") || (strings.Contains(content, "BEGIN PRIVATE KEY") && len(content) > 1000) {
		results = append(results, Result{
			File:              fmt.Sprintf("secret/%s/%s (%s)", secretName, key, namespace),
			Algorithm:         "RSA",
			Type:              "PublicKey",
			Line:              1,
			Method:            "TLS Certificate Analysis",
			Risk:              "High",
			VulnerabilityType: "Shor's Algorithm",
			Description:       "TLS certificate/key uses RSA algorithm vulnerable to quantum attacks",
			Recommendation:    "Replace with post-quantum certificate when available from CA",
		})
	}

	// Check for ECDSA certificates
	if strings.Contains(content, "EC PRIVATE KEY") || strings.Contains(content, "prime256v1") || strings.Contains(content, "secp") {
		results = append(results, Result{
			File:              fmt.Sprintf("secret/%s/%s (%s)", secretName, key, namespace),
			Algorithm:         "ECDSA",
			Type:              "PublicKey",
			Line:              1,
			Method:            "TLS Certificate Analysis",
			Risk:              "High",
			VulnerabilityType: "Shor's Algorithm",
			Description:       "TLS certificate/key uses ECDSA algorithm vulnerable to quantum attacks",
			Recommendation:    "Replace with post-quantum certificate when available from CA",
		})
	}

	return results
}

// scanConfigMaps scans Kubernetes ConfigMaps for crypto configurations
func (k *K8sScanner) scanConfigMaps(namespaces []string) ([]Result, int) {
	var results []Result
	assetCount := 0

	for _, namespace := range namespaces {
		if k.scanner.Verbose {
			fmt.Printf("Scanning ConfigMaps in namespace: %s\n", namespace)
		}

		configMapList, err := k.clientset.CoreV1().ConfigMaps(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			if k.scanner.Verbose {
				fmt.Printf("Error listing ConfigMaps in namespace %s: %v\n", namespace, err)
			}
			continue
		}

		for _, configMap := range configMapList.Items {
			assetCount++
			configMapResults := k.analyzeConfigMap(configMap.Name, namespace, configMap.Data)
			results = append(results, configMapResults...)
		}
	}

	return results, assetCount
}

// analyzeConfigMap analyzes a ConfigMap for crypto configurations
func (k *K8sScanner) analyzeConfigMap(configMapName, namespace string, data map[string]string) []Result {
	var results []Result

	for key, content := range data {
		lines := strings.Split(content, "\n")
		for lineNum, line := range lines {
			for _, rule := range k.scanner.Rules {
				if match, _ := regexp.MatchString(rule.Pattern, line); match {
					results = append(results, Result{
						File:              fmt.Sprintf("configmap/%s/%s (%s)", configMapName, key, namespace),
						Algorithm:         rule.AlgorithmName,
						Type:              rule.AlgorithmType,
						Line:              lineNum + 1,
						Method:            "Kubernetes ConfigMap Analysis",
						Risk:              rule.RiskLevel,
						VulnerabilityType: rule.VulnerabilityType,
						Description:       fmt.Sprintf("ConfigMap contains crypto configuration: %s", rule.Description),
						Recommendation:    rule.Recommendation,
					})
				}
			}
		}
	}

	return results
}

// scanContainerImages scans container images in pods (placeholder implementation)
func (k *K8sScanner) scanContainerImages(namespaces []string) ([]Result, int) {
	var results []Result
	assetCount := 0

	for _, namespace := range namespaces {
		if k.scanner.Verbose {
			fmt.Printf("Scanning container images in namespace: %s\n", namespace)
		}

		podList, err := k.clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			if k.scanner.Verbose {
				fmt.Printf("Error listing pods in namespace %s: %v\n", namespace, err)
			}
			continue
		}

		for _, pod := range podList.Items {
			for _, container := range pod.Spec.Containers {
				assetCount++
				// Placeholder: In a real implementation, this would scan the container image
				// For now, just check if common crypto libraries might be present based on image name
				imageResults := k.analyzeContainerImage(pod.Name, namespace, container.Name, container.Image)
				results = append(results, imageResults...)
			}
		}
	}

	return results, assetCount
}

// analyzeContainerImage analyzes container images for crypto libraries (placeholder)
func (k *K8sScanner) analyzeContainerImage(podName, namespace, containerName, image string) []Result {
	var results []Result

	// Placeholder logic - in reality this would scan the actual image layers
	// For now, make educated guesses based on common patterns
	
	if strings.Contains(image, "openssl") || strings.Contains(image, "ssl") {
		results = append(results, Result{
			File:              fmt.Sprintf("pod/%s/container/%s (%s)", podName, containerName, namespace),
			Algorithm:         "RSA",
			Type:              "PublicKey",
			Line:              1,
			Method:            "Container Image Analysis",
			Risk:              "High",
			VulnerabilityType: "Shor's Algorithm",
			Description:       fmt.Sprintf("Container image %s likely contains OpenSSL with RSA support", image),
			Recommendation:    "Verify image contents and upgrade to post-quantum cryptography when available",
		})
	}

	return results
}

// scanNetworkPolicies scans network policies (placeholder)
func (k *K8sScanner) scanNetworkPolicies(namespaces []string) ([]Result, int) {
	var results []Result
	assetCount := 0

	for _, namespace := range namespaces {
		networkPolicyList, err := k.clientset.NetworkingV1().NetworkPolicies(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			continue
		}

		assetCount += len(networkPolicyList.Items)
		// Placeholder - network policies don't typically contain crypto directly
	}

	return results, assetCount
}

// scanIngresses scans ingress configurations (placeholder)
func (k *K8sScanner) scanIngresses(namespaces []string) ([]Result, int) {
	var results []Result
	assetCount := 0

	for _, namespace := range namespaces {
		ingressList, err := k.clientset.NetworkingV1().Ingresses(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, ingress := range ingressList.Items {
			assetCount++
			// Check TLS configuration in ingresses
			for _, tls := range ingress.Spec.TLS {
				if tls.SecretName != "" {
					results = append(results, Result{
						File:              fmt.Sprintf("ingress/%s/tls/%s (%s)", ingress.Name, tls.SecretName, namespace),
						Algorithm:         "TLS",
						Type:              "PublicKey",
						Line:              1,
						Method:            "Ingress TLS Analysis",
						Risk:              "High",
						VulnerabilityType: "Shor's Algorithm",
						Description:       "Ingress uses TLS certificate that may contain quantum-vulnerable algorithms",
						Recommendation:    "Verify TLS certificate uses post-quantum algorithms",
					})
				}
			}
		}
	}

	return results, assetCount
}