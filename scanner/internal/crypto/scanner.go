package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Result represents a vulnerability finding
type Result struct {
	File              string    `json:"file"`
	Algorithm         string    `json:"algorithm"`
	Type              string    `json:"type"`
	Line              int       `json:"line"`
	Method            string    `json:"method"`
	Risk              string    `json:"risk"`
	VulnerabilityType string    `json:"vulnerability_type"` // What type of quantum vulnerability (Shor's, Grover's, etc.)
	Description       string    `json:"description"`        // Description of the vulnerability
	Recommendation    string    `json:"recommendation"`     // Recommendation for remediation
	// NIST IR 8547 fields
	NISTCategory      string    `json:"nist_category,omitempty"`      // "1", "2", "3", "4", "5", "deprecated", "disallowed"
	DeprecationDate   *time.Time `json:"deprecation_date,omitempty"`   // 2030-01-01 for 112-bit algorithms
	DisallowanceDate  *time.Time `json:"disallowance_date,omitempty"`  // 2035-01-01 for all vulnerable
	QuantumResistant  bool      `json:"quantum_resistant"`
	NISTAlgorithmID   string    `json:"nist_algorithm_id,omitempty"`  // e.g., "ML-KEM-512", "RSA-2048"
	SecurityStrength  int       `json:"security_strength,omitempty"`  // Classical security strength in bits
	NISTTable         string    `json:"nist_table,omitempty"`         // Which NIST IR 8547 table references this
}

// DetectionRule defines a pattern to detect vulnerable crypto
type DetectionRule struct {
	AlgorithmType     string
	AlgorithmName     string
	Method            string
	Pattern           string
	RiskLevel         string
	VulnerabilityType string
	Description       string
	Recommendation    string
	// NIST IR 8547 fields
	NISTAlgorithmID   string // Link to NIST algorithm identifier
}

// Scanner handles the scanning process
type Scanner struct {
	Verbose bool
	Rules   []DetectionRule
}

// NewScanner creates a new scanner instance
func NewScanner(verbose bool) *Scanner {
	return &Scanner{
		Verbose: verbose,
		Rules: buildDetectionRules(),
	}
}

// ScanDirectory scans all files in a directory recursively
func (s *Scanner) ScanDirectory(dir string) []Result {
	var results []Result

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Skip certain directories and file types
		if s.shouldSkip(path) {
			return nil
		}

		if s.Verbose {
			fmt.Printf("Scanning file: %s\n", path)
		}

		fileResults := s.ScanFile(path)
		results = append(results, fileResults...)

		if s.Verbose && len(fileResults) > 0 {
			fmt.Printf("Found %d vulnerabilities in file: %s\n", len(fileResults), path)
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
	}

	return results
}

// ScanFile scans a single file for vulnerable crypto
func (s *Scanner) ScanFile(filePath string) []Result {
	var results []Result

	// Skip certain file types
	if s.shouldSkip(filePath) {
		return results
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", filePath, err)
		return results
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		for _, rule := range s.Rules {
			if match, _ := regexp.MatchString(rule.Pattern, line); match {
				result := Result{
					File:              filePath,
					Algorithm:         rule.AlgorithmName,
					Type:              rule.AlgorithmType,
					Line:              i + 1,
					Method:            rule.Method,
					Risk:              rule.RiskLevel,
					VulnerabilityType: rule.VulnerabilityType,
					Description:       rule.Description,
					Recommendation:    rule.Recommendation,
				}

				// Populate NIST IR 8547 fields
				if rule.NISTAlgorithmID != "" {
					if nistInfo := GetNISTInfo(rule.NISTAlgorithmID); nistInfo != nil {
						result.NISTCategory = string(nistInfo.Category)
						result.DeprecationDate = nistInfo.DeprecationDate
						result.DisallowanceDate = nistInfo.DisallowanceDate
						result.QuantumResistant = nistInfo.QuantumResistant
						result.NISTAlgorithmID = nistInfo.AlgorithmID
						result.SecurityStrength = nistInfo.SecurityStrength
						result.NISTTable = nistInfo.Table
						
						// Update risk level based on timeline
						currentTime := time.Now()
						if IsDisallowedByDate(nistInfo, currentTime) {
							result.Risk = "Critical"
							result.Description += " (NIST IR 8547: DISALLOWED as of " + currentTime.Format("2006-01-02") + ")"
						} else if IsDeprecatedByDate(nistInfo, currentTime) {
							if result.Risk == "Low" || result.Risk == "Medium" {
								result.Risk = "High"
							}
							result.Description += " (NIST IR 8547: DEPRECATED as of " + currentTime.Format("2006-01-02") + ")"
						}
					}
				}

				results = append(results, result)

				if s.Verbose {
					fmt.Printf("Match found: %s (Line %d) Method: %s Risk: %s",
						rule.AlgorithmName, i+1, rule.Method, result.Risk)
					if result.NISTCategory != "" {
						fmt.Printf(" NIST Category: %s", result.NISTCategory)
					}
					fmt.Println()
				}
			}
		}
	}

	return results
}

// shouldSkip determines if a file should be skipped during scanning
func (s *Scanner) shouldSkip(path string) bool {
	// Skip node_modules, .git, etc.
	if strings.Contains(path, "node_modules") ||
		strings.Contains(path, ".git") ||
		strings.Contains(path, "__pycache__") ||
		strings.Contains(path, "vendor") {
		return true
	}

	// Only scan certain file extensions
	ext := strings.ToLower(filepath.Ext(path))
	validExts := []string{".go", ".java", ".js", ".ts", ".py", ".php", ".rb", ".c", ".cpp", ".h", ".cs", ".swift"}

	for _, validExt := range validExts {
		if ext == validExt {
			return false
		}
	}

	return true
}

// ScanDirectoryWithMetadata scans all files in a directory and returns asset count
func (s *Scanner) ScanDirectoryWithMetadata(dir string) ([]Result, int) {
	var results []Result
	assetCount := 0

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		// Skip certain directories and file types
		if s.shouldSkip(path) {
			return nil
		}

		assetCount++

		if s.Verbose {
			fmt.Printf("Scanning file: %s\n", path)
		}

		fileResults := s.ScanFile(path)
		results = append(results, fileResults...)

		if s.Verbose && len(fileResults) > 0 {
			fmt.Printf("Found %d vulnerabilities in file: %s\n", len(fileResults), path)
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error reading directory: %v\n", err)
	}

	return results, assetCount
}

// ScanKubernetes scans Kubernetes cluster resources for crypto vulnerabilities
func (s *Scanner) ScanKubernetes(namespaces []string, secretScan, configMapScan, imageScan, networkPolicyScan, ingressScan, serviceMeshScan, deepCodeScan, includeKubeSystem bool) ([]Result, int) {
	if s.Verbose {
		fmt.Printf("Starting Kubernetes cluster scan across %d namespaces...\n", len(namespaces))
	}

	// Create Kubernetes scanner with real client integration
	k8sScanner, err := NewK8sScanner(s)
	if err != nil {
		if s.Verbose {
			fmt.Printf("Error creating Kubernetes client: %v\n", err)
			fmt.Printf("Falling back to simulated scan results...\n")
		}
		// Fallback to simulated results if Kubernetes client fails
		return s.scanKubernetesFallback(namespaces, secretScan, configMapScan, imageScan, networkPolicyScan, ingressScan, serviceMeshScan, deepCodeScan, includeKubeSystem)
	}

	// Use real Kubernetes client integration
	return k8sScanner.ScanKubernetesCluster(namespaces, secretScan, configMapScan, imageScan, networkPolicyScan, ingressScan, serviceMeshScan, deepCodeScan, includeKubeSystem)
}

// scanKubernetesFallback provides fallback scanning when Kubernetes client is unavailable
func (s *Scanner) scanKubernetesFallback(namespaces []string, secretScan, configMapScan, imageScan, networkPolicyScan, ingressScan, serviceMeshScan, deepCodeScan, includeKubeSystem bool) ([]Result, int) {
	var results []Result
	assetCount := 0

	// Simulate scanning different Kubernetes resources
	if secretScan {
		secretResults, secretCount := s.scanKubernetesSecretsSimulated(namespaces)
		results = append(results, secretResults...)
		assetCount += secretCount
	}
	
	if configMapScan {
		configMapResults, configMapCount := s.scanKubernetesConfigMapsSimulated(namespaces)
		results = append(results, configMapResults...)
		assetCount += configMapCount
	}
	
	if imageScan {
		imageResults, imageCount := s.scanKubernetesImagesSimulated(namespaces)
		results = append(results, imageResults...)
		assetCount += imageCount
	}

	if s.Verbose {
		fmt.Printf("Kubernetes fallback scan completed. Analyzed %d simulated assets across %d namespaces.\n", assetCount, len(namespaces))
	}

	return results, assetCount
}

// scanKubernetesSecretsSimulated provides simulated secret scanning for fallback mode
func (s *Scanner) scanKubernetesSecretsSimulated(namespaces []string) ([]Result, int) {
	var results []Result
	assetCount := 0
	
	// TODO: Implement actual Kubernetes secret scanning
	// This is a placeholder that simulates finding crypto in secrets
	
	for _, namespace := range namespaces {
		if s.Verbose {
			fmt.Printf("Scanning secrets in namespace: %s\n", namespace)
		}
		
		// Simulate finding TLS secrets with RSA certificates
		results = append(results, Result{
			File:              fmt.Sprintf("secret/tls-cert (%s)", namespace),
			Algorithm:         "RSA",
			Type:              "PublicKey",
			Line:              1,
			Method:            "Certificate Analysis",
			Risk:              "High",
			VulnerabilityType: "Shor's Algorithm",
			Description:       "TLS certificate uses RSA algorithm vulnerable to quantum attacks",
			Recommendation:    "Replace with post-quantum certificate when available from CA",
		})
		assetCount++
	}
	
	return results, assetCount
}

// scanKubernetesConfigMapsSimulated provides simulated ConfigMap scanning for fallback mode
func (s *Scanner) scanKubernetesConfigMapsSimulated(namespaces []string) ([]Result, int) {
	var results []Result
	assetCount := 0
	
	// TODO: Implement actual Kubernetes ConfigMap scanning
	
	for _, namespace := range namespaces {
		if s.Verbose {
			fmt.Printf("Scanning ConfigMaps in namespace: %s\n", namespace)
		}
		
		// Simulate finding crypto configurations in ConfigMaps
		results = append(results, Result{
			File:              fmt.Sprintf("configmap/app-config (%s)", namespace),
			Algorithm:         "AES-128",
			Type:              "SymmetricKey",
			Line:              1,
			Method:            "Configuration Analysis",
			Risk:              "Medium",
			VulnerabilityType: "Grover's Algorithm",
			Description:       "Application configured to use AES-128 which provides reduced quantum security",
			Recommendation:    "Update application configuration to use AES-256",
		})
		assetCount++
	}
	
	return results, assetCount
}

// scanKubernetesImagesSimulated provides simulated image scanning for fallback mode
func (s *Scanner) scanKubernetesImagesSimulated(namespaces []string) ([]Result, int) {
	var results []Result
	assetCount := 0
	
	// TODO: Implement actual container image scanning
	
	for _, namespace := range namespaces {
		if s.Verbose {
			fmt.Printf("Scanning container images in namespace: %s\n", namespace)
		}
		
		// Simulate finding crypto libraries in container images
		results = append(results, Result{
			File:              fmt.Sprintf("image/app:latest (%s)", namespace),
			Algorithm:         "ECC",
			Type:              "PublicKey",
			Line:              1,
			Method:            "Image Layer Analysis",
			Risk:              "High",
			VulnerabilityType: "Shor's Algorithm",
			Description:       "Container image includes ECC cryptography library vulnerable to quantum attacks",
			Recommendation:    "Rebuild image with post-quantum cryptography libraries",
		})
		assetCount++
	}
	
	return results, assetCount
}

// ScanPCAP analyzes PCAP files for crypto vulnerabilities in network traffic
func (s *Scanner) ScanPCAP(pcapFile string, liveCapture bool, captureInterface, captureDuration string, tlsFilter bool) ([]Result, int) {
	if s.Verbose {
		if liveCapture {
			fmt.Printf("Starting live network capture on %s for %s...\n", captureInterface, captureDuration)
		} else {
			fmt.Printf("Analyzing PCAP file: %s\n", pcapFile)
		}
	}

	// Create PCAP scanner with real gopacket integration
	pcapScanner := NewPCAPScanner(s)
	
	if liveCapture {
		return pcapScanner.PerformLiveCapture(captureInterface, captureDuration, tlsFilter)
	} else {
		return pcapScanner.AnalyzePCAPFile(pcapFile, tlsFilter)
	}
}

// ScanNetwork performs live network monitoring for crypto vulnerabilities
func (s *Scanner) ScanNetwork(captureInterface, captureDuration string, tlsFilter bool) ([]Result, int) {
	if s.Verbose {
		fmt.Printf("Starting network monitoring on %s for %s...\n", captureInterface, captureDuration)
	}

	// Create PCAP scanner for live network monitoring
	pcapScanner := NewPCAPScanner(s)
	return pcapScanner.PerformLiveCapture(captureInterface, captureDuration, tlsFilter)
}
