package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"qvs-pro/scanner/internal/crypto"
)

// ScanMetadata contains metadata about the scanning process
type ScanMetadata struct {
	Mode        string    `json:"mode"`
	Target      string    `json:"target"`
	TotalAssets int       `json:"total_assets"`
	ScanTime    string    `json:"scan_time"`
	Namespaces  []string  `json:"namespaces,omitempty"`
	Duration    string    `json:"duration,omitempty"`
}

// CBOMReport represents a comprehensive CBOM (Cryptographic Bill of Materials) report
type CBOMReport struct {
	BOMFormat   string                  `json:"bomFormat"`
	SpecVersion string                  `json:"specVersion"`
	SerialNumber string                 `json:"serialNumber"`
	Version     int                     `json:"version"`
	Metadata    CBOMMetadata            `json:"metadata"`
	Components  []CBOMComponent         `json:"components"`
	Findings    []crypto.Result         `json:"findings"`
	Summary     CBOMSummary             `json:"summary"`
}

// CBOMMetadata contains metadata about the CBOM report
type CBOMMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []CBOMTool   `json:"tools"`
	Authors   []CBOMAuthor `json:"authors"`
	Supplier  CBOMSupplier `json:"supplier"`
}

// CBOMTool represents the scanning tool information
type CBOMTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CBOMAuthor represents the author information
type CBOMAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// CBOMSupplier represents the supplier information
type CBOMSupplier struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// CBOMComponent represents a scanned component/asset
type CBOMComponent struct {
	Type      string            `json:"type"`
	BOMRef    string            `json:"bom-ref"`
	Name      string            `json:"name"`
	Version   string            `json:"version,omitempty"`
	Scope     string            `json:"scope"`
	Hashes    []CBOMHash        `json:"hashes,omitempty"`
	Licenses  []CBOMLicense     `json:"licenses,omitempty"`
	Crypto    CBOMCrypto        `json:"crypto,omitempty"`
	Evidence  CBOMEvidence      `json:"evidence,omitempty"`
}

// CBOMHash represents file hashes
type CBOMHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// CBOMLicense represents license information
type CBOMLicense struct {
	License CBOMLicenseChoice `json:"license"`
}

// CBOMLicenseChoice represents license choice
type CBOMLicenseChoice struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CBOMCrypto represents cryptographic information
type CBOMCrypto struct {
	Algorithm     string `json:"algorithm"`
	KeySize       int    `json:"keySize,omitempty"`
	Purpose       string `json:"purpose"`
	QuantumSafe   bool   `json:"quantumSafe"`
	QuantumRisk   string `json:"quantumRisk"`
}

// CBOMEvidence represents evidence of where crypto was found
type CBOMEvidence struct {
	Identity []CBOMIdentity `json:"identity"`
}

// CBOMIdentity represents identity evidence
type CBOMIdentity struct {
	Field      string `json:"field"`
	Confidence float64 `json:"confidence"`
	Methods    []string `json:"methods"`
}

// CBOMSummary provides a summary of the scan results
type CBOMSummary struct {
	TotalAssets      int                    `json:"total_assets"`
	VulnerableAssets int                    `json:"vulnerable_assets"`
	QuantumSafeAssets int                   `json:"quantum_safe_assets"`
	RiskBreakdown    map[string]int         `json:"risk_breakdown"`
	AlgorithmBreakdown map[string]int       `json:"algorithm_breakdown"`
	ScanDuration     string                 `json:"scan_duration"`
}

// GetCurrentTimestamp returns the current timestamp in ISO format
func GetCurrentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// OutputJSON outputs scan results in JSON format
func OutputJSON(results interface{}) {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error converting to JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonData))
}

// OutputText outputs scan results in human-readable text format
func OutputText(results interface{}) {
	// Type assertion to access the Result struct fields
	typedResults, ok := results.([]crypto.Result)

	if !ok {
		fmt.Println("Error: Could not format results")
		return
	}

	if len(typedResults) == 0 {
		fmt.Println("No vulnerabilities found.")
		return
	}

	fmt.Printf("Found %d potential vulnerabilities:\n\n", len(typedResults))
	for _, result := range typedResults {
		fmt.Printf("File: %s\n", result.File)
		fmt.Printf("Algorithm: %s (%s)\n", result.Algorithm, result.Type)
		fmt.Printf("Line: %d\n", result.Line)
		fmt.Printf("Method: %s\n", result.Method)
		fmt.Printf("Risk Level: %s\n", result.Risk)
		fmt.Println("----------------------")
	}
}

// OutputCBOM outputs scan results in CBOM (Cryptographic Bill of Materials) format
func OutputCBOM(results []crypto.Result, metadata ScanMetadata, mode string) {
	report := generateCBOMReport(results, metadata, mode)
	
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Printf("Error converting CBOM to JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(jsonData))
}

// generateCBOMReport creates a comprehensive CBOM report
func generateCBOMReport(results []crypto.Result, metadata ScanMetadata, mode string) CBOMReport {
	timestamp := GetCurrentTimestamp()
	
	// Generate unique serial number based on timestamp and target
	serialNumber := fmt.Sprintf("urn:uuid:qvs-pro-%s-%d", mode, time.Now().Unix())
	
	// Create components from scan results
	components := make([]CBOMComponent, 0)
	algorithmBreakdown := make(map[string]int)
	riskBreakdown := make(map[string]int)
	vulnerableAssets := 0
	quantumSafeAssets := 0
	
	// Process results to create components and statistics
	processedFiles := make(map[string]bool)
	
	for _, result := range results {
		// Count algorithm usage
		algorithmBreakdown[result.Algorithm]++
		riskBreakdown[result.Risk]++
		
		// Count vulnerable vs quantum-safe assets
		if result.Type == "PostQuantum" {
			quantumSafeAssets++
		} else if result.Risk == "High" || result.Risk == "Medium" {
			vulnerableAssets++
		}
		
		// Create component if file not already processed
		if !processedFiles[result.File] {
			component := CBOMComponent{
				Type:    "file",
				BOMRef:  fmt.Sprintf("file-%d", len(components)),
				Name:    result.File,
				Scope:   "required",
				Crypto: CBOMCrypto{
					Algorithm:   result.Algorithm,
					Purpose:     result.Type,
					QuantumSafe: result.Type == "PostQuantum",
					QuantumRisk: result.VulnerabilityType,
				},
				Evidence: CBOMEvidence{
					Identity: []CBOMIdentity{
						{
							Field:      "source-code",
							Confidence: 0.95,
							Methods:    []string{"regex-pattern-matching", "static-analysis"},
						},
					},
				},
			}
			components = append(components, component)
			processedFiles[result.File] = true
		}
	}
	
	// Create CBOM metadata
	cbomMetadata := CBOMMetadata{
		Timestamp: timestamp,
		Tools: []CBOMTool{
			{
				Vendor:  "QVS-Pro",
				Name:    "qvs-pro-scanner",
				Version: "2.0.0",
			},
		},
		Authors: []CBOMAuthor{
			{
				Name:  "QVS-Pro Scanner",
				Email: "scanner@qvs-pro.com",
			},
		},
		Supplier: CBOMSupplier{
			Name: "QVS-Pro",
			URL:  "https://qvs-pro.com",
		},
	}
	
	// Create summary
	summary := CBOMSummary{
		TotalAssets:        metadata.TotalAssets,
		VulnerableAssets:   vulnerableAssets,
		QuantumSafeAssets:  quantumSafeAssets,
		RiskBreakdown:      riskBreakdown,
		AlgorithmBreakdown: algorithmBreakdown,
		ScanDuration:       metadata.Duration,
	}
	
	// Create the complete CBOM report
	report := CBOMReport{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		SerialNumber: serialNumber,
		Version:      1,
		Metadata:     cbomMetadata,
		Components:   components,
		Findings:     results,
		Summary:      summary,
	}
	
	return report
}
