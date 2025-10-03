package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aqua-cbom/migrator/internal/migration"
)

const version = "1.0.0"

func main() {
	// CLI flags
	cbomFile := flag.String("cbom", "", "Path to CBOM JSON file")
	outputFile := flag.String("output", "", "Path to output migration plan JSON (default: cbom-basename-migration-plan.json)")
	context := flag.String("context", "", "Deployment context (edge_ingress, service_mesh, etc.)")
	timeline := flag.String("timeline", "", "Target timeline (e.g., 2025-Q2)")
	rulesFile := flag.String("rules", "migration-rules.yaml", "Path to migration rules YAML")
	versionFlag := flag.Bool("version", false, "Print version")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("aqua-cbom-migrator v%s\n", version)
		os.Exit(0)
	}

	if *cbomFile == "" {
		fmt.Fprintln(os.Stderr, "Error: -cbom flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Read CBOM file
	cbomData, err := os.ReadFile(*cbomFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CBOM file: %v\n", err)
		os.Exit(1)
	}

	var cbom map[string]interface{}
	if err := json.Unmarshal(cbomData, &cbom); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing CBOM JSON: %v\n", err)
		os.Exit(1)
	}

	// Load migration rules
	rules, err := migration.LoadRules(*rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading migration rules: %v\n", err)
		os.Exit(1)
	}

	// Generate migration plan
	planner := migration.NewPlanner(rules, *context, *timeline)
	plan := planner.GeneratePlan(cbom)

	// Determine output file
	outPath := *outputFile
	if outPath == "" {
		// Default: cbom-basename-migration-plan.json
		baseName := strings.TrimSuffix(*cbomFile, ".json")
		outPath = baseName + "-migration-plan.json"
	}

	// Write migration plan
	planJSON, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling migration plan: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outPath, planJSON, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing migration plan: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Migration plan written to: %s\n", outPath)
}
