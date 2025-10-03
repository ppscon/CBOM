package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"qvs-pro/scanner/internal/crypto"
	"qvs-pro/scanner/internal/migration"
	"qvs-pro/scanner/internal/utils"
)

const version = "2.0.0"

func main() {
	// Define command-line flags
	mode := flag.String("mode", "file", "Scan mode: file, k8s, cluster-scan, pcap, network")
	dirToScan := flag.String("dir", "", "Directory or file to scan (default: current directory)")
	namespaces := flag.String("namespace", "", "Kubernetes namespaces to scan (comma-separated)")
	pcapFile := flag.String("pcap-file", "", "PCAP file to analyze")
	outputJSON := flag.Bool("json", false, "Output results as JSON")
	outputCBOM := flag.Bool("output-cbom", false, "Output results in CBOM format")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	versionFlag := flag.Bool("version", false, "Print the version")
	
	// Kubernetes-specific flags (for operator compatibility)
	secretScan := flag.Bool("secret-scan", true, "Scan Kubernetes secrets")
	configMapScan := flag.Bool("configmap-scan", true, "Scan Kubernetes ConfigMaps")
	imageScan := flag.Bool("image-scan", false, "Scan container images")
	networkPolicyScan := flag.Bool("network-policy-scan", false, "Scan network policies")
	ingressScan := flag.Bool("ingress-scan", false, "Scan ingress configurations")
	serviceMeshScan := flag.Bool("service-mesh-scan", false, "Scan service mesh configurations")
	deepCodeScan := flag.Bool("deep-code-scan", false, "Deep scan of application code")
	includeKubeSystem := flag.Bool("include-kube-system", false, "Include kube-system namespace")
	timeout := flag.String("timeout", "1200s", "Scan timeout duration")
	
	// PCAP-specific flags
	liveCapture := flag.Bool("live-capture", false, "Capture live network traffic")
	captureInterface := flag.String("interface", "eth0", "Network interface for live capture")
	captureDuration := flag.String("duration", "60s", "Duration for live capture")
	tlsFilter := flag.Bool("tls-only", false, "Filter only TLS/SSL traffic")

	// Migration planning flags
	migrationPlan := flag.Bool("migration-plan", false, "Generate PQC migration plan")
	migrationContext := flag.String("migration-context", "", "Deployment context (edge_ingress, service_mesh, internal_api, etc.)")
	migrationTimeline := flag.String("migration-timeline", "", "Target timeline (e.g., 2025-Q2)")
	migrationRulesFile := flag.String("migration-rules", "migration-rules.yaml", "Path to migration rules file")

	// Parse command-line flags
	flag.Parse()

	// Check if version flag is set
	if *versionFlag {
		fmt.Printf("Aqua-CBOM Scanner v%s\n", version)
		fmt.Printf("Modes: file, k8s, cluster-scan, pcap, network\n")
		fmt.Printf("Migration Planning: Supported (use -migration-plan flag)\n")
		return
	}

	if *verbose {
		fmt.Printf("Aqua-CBOM Scanner v%s\n", version)
		fmt.Printf("Mode: %s\n", *mode)
	}

	var results []crypto.Result
	var scanMetadata utils.ScanMetadata
	
	scanner := crypto.NewScanner(*verbose)

	// Route to appropriate scan mode
	switch *mode {
	case "file":
		results, scanMetadata = handleFileMode(scanner, dirToScan, verbose)
	case "k8s", "cluster-scan":
		results, scanMetadata = handleKubernetesMode(scanner, namespaces, secretScan, configMapScan, imageScan, networkPolicyScan, ingressScan, serviceMeshScan, deepCodeScan, includeKubeSystem, timeout, verbose)
	case "pcap":
		results, scanMetadata = handlePCAPMode(scanner, pcapFile, liveCapture, captureInterface, captureDuration, tlsFilter, verbose)
	case "network":
		results, scanMetadata = handleNetworkMode(scanner, captureInterface, captureDuration, tlsFilter, verbose)
	default:
		fmt.Printf("Error: Unsupported mode '%s'. Use: file, k8s, cluster-scan, pcap, network\n", *mode)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("\nScan complete. Found %d potential vulnerabilities across %d assets.\n\n", len(results), scanMetadata.TotalAssets)
	}

	// Output results in requested format
	if *outputCBOM {
		utils.OutputCBOM(results, scanMetadata, *mode)

		// Generate migration plan if requested
		if *migrationPlan && len(results) > 0 {
			if *verbose {
				fmt.Fprintf(os.Stderr, "\nGenerating PQC migration plan...\n")
			}

			// Load migration rules
			rules, err := migration.LoadRules(*migrationRulesFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to load migration rules: %v\n", err)
				fmt.Fprintf(os.Stderr, "Skipping migration plan generation.\n")
			} else {
				// Generate plan
				plan := migration.GeneratePlan(results, rules, *migrationContext, *migrationTimeline)

				// Write to stderr (separate from CBOM JSON on stdout)
				fmt.Fprintf(os.Stderr, "\n=== PQC Migration Plan ===\n")
				fmt.Fprintf(os.Stderr, "Total Findings: %d\n", plan.Summary.TotalFindings)
				if plan.Summary.DeploymentContext != "" {
					fmt.Fprintf(os.Stderr, "Context: %s\n", plan.Summary.DeploymentContext)
				}
				if plan.Summary.TargetTimeline != "" {
					fmt.Fprintf(os.Stderr, "Timeline: %s\n", plan.Summary.TargetTimeline)
				}
				fmt.Fprintf(os.Stderr, "\nPriority Breakdown:\n")
				for priority, count := range plan.Summary.ByPriority {
					fmt.Fprintf(os.Stderr, "  %s: %d\n", priority, count)
				}
				fmt.Fprintf(os.Stderr, "\nReadiness Breakdown:\n")
				for readiness, count := range plan.Summary.ByReadiness {
					fmt.Fprintf(os.Stderr, "  %s: %d\n", readiness, count)
				}

				if *verbose {
					fmt.Fprintf(os.Stderr, "\nMigration plan details available in CBOM output.\n")
				}
			}
		}
	} else if *outputJSON {
		utils.OutputJSON(results)
	} else {
		utils.OutputText(results)
	}
}

// handleFileMode processes traditional file/directory scanning
func handleFileMode(scanner *crypto.Scanner, dirToScan *string, verbose *bool) ([]crypto.Result, utils.ScanMetadata) {
	// If no directory specified, use current directory
	if *dirToScan == "" {
		currentDir, err := os.Getwd()
		if err != nil {
			fmt.Printf("Error getting current directory: %v\n", err)
			os.Exit(1)
		}
		*dirToScan = currentDir
	}

	absPath, err := filepath.Abs(*dirToScan)
	if err != nil {
		fmt.Printf("Error resolving path: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("Scanning: %s\n", absPath)
	}

	fileInfo, err := os.Stat(absPath)
	if err != nil {
		fmt.Printf("Error reading path: %v\n", err)
		os.Exit(1)
	}

	var results []crypto.Result
	var assetCount int

	if fileInfo.IsDir() {
		results, assetCount = scanner.ScanDirectoryWithMetadata(absPath)
	} else {
		result := scanner.ScanFile(absPath)
		results = result
		assetCount = 1
	}

	metadata := utils.ScanMetadata{
		Mode:        "file",
		Target:      absPath,
		TotalAssets: assetCount,
		ScanTime:    utils.GetCurrentTimestamp(),
	}

	return results, metadata
}

// handleKubernetesMode processes Kubernetes cluster scanning
func handleKubernetesMode(scanner *crypto.Scanner, namespaces *string, secretScan, configMapScan, imageScan, networkPolicyScan, ingressScan, serviceMeshScan, deepCodeScan, includeKubeSystem *bool, timeout *string, verbose *bool) ([]crypto.Result, utils.ScanMetadata) {
	if *verbose {
		fmt.Printf("Starting Kubernetes cluster scan...\n")
		if *namespaces != "" {
			fmt.Printf("Target namespaces: %s\n", *namespaces)
		} else {
			fmt.Printf("Scanning all accessible namespaces\n")
		}
	}

	// Parse namespaces
	var targetNamespaces []string
	if *namespaces != "" {
		targetNamespaces = strings.Split(*namespaces, ",")
		// Trim whitespace
		for i, ns := range targetNamespaces {
			targetNamespaces[i] = strings.TrimSpace(ns)
		}
	}

	// Perform Kubernetes scanning
	results, assetCount := scanner.ScanKubernetes(targetNamespaces, *secretScan, *configMapScan, *imageScan, *networkPolicyScan, *ingressScan, *serviceMeshScan, *deepCodeScan, *includeKubeSystem)

	metadata := utils.ScanMetadata{
		Mode:        "kubernetes",
		Target:      strings.Join(targetNamespaces, ","),
		TotalAssets: assetCount,
		ScanTime:    utils.GetCurrentTimestamp(),
		Namespaces:  targetNamespaces,
	}

	return results, metadata
}

// handlePCAPMode processes PCAP file analysis
func handlePCAPMode(scanner *crypto.Scanner, pcapFile *string, liveCapture *bool, captureInterface, captureDuration *string, tlsFilter *bool, verbose *bool) ([]crypto.Result, utils.ScanMetadata) {
	if *verbose {
		if *liveCapture {
			fmt.Printf("Starting live network capture on interface %s for %s...\n", *captureInterface, *captureDuration)
		} else {
			fmt.Printf("Analyzing PCAP file: %s\n", *pcapFile)
		}
	}

	// Perform PCAP analysis
	results, assetCount := scanner.ScanPCAP(*pcapFile, *liveCapture, *captureInterface, *captureDuration, *tlsFilter)

	target := *pcapFile
	if *liveCapture {
		target = fmt.Sprintf("%s (live:%s)", *captureInterface, *captureDuration)
	}

	metadata := utils.ScanMetadata{
		Mode:        "pcap",
		Target:      target,
		TotalAssets: assetCount,
		ScanTime:    utils.GetCurrentTimestamp(),
	}

	return results, metadata
}

// handleNetworkMode processes live network monitoring
func handleNetworkMode(scanner *crypto.Scanner, captureInterface, captureDuration *string, tlsFilter *bool, verbose *bool) ([]crypto.Result, utils.ScanMetadata) {
	if *verbose {
		fmt.Printf("Starting network monitoring on interface %s for %s...\n", *captureInterface, *captureDuration)
	}

	// Perform network monitoring
	results, assetCount := scanner.ScanNetwork(*captureInterface, *captureDuration, *tlsFilter)

	metadata := utils.ScanMetadata{
		Mode:        "network",
		Target:      fmt.Sprintf("%s (duration:%s)", *captureInterface, *captureDuration),
		TotalAssets: assetCount,
		ScanTime:    utils.GetCurrentTimestamp(),
	}

	return results, metadata
}
