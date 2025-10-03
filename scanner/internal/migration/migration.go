package migration

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
	"qvs-pro/scanner/internal/crypto"
)

// MigrationRules represents the complete migration rules configuration
type MigrationRules struct {
	Version          string                       `yaml:"version"`
	LastUpdated      string                       `yaml:"last_updated"`
	MigrationMatrix  MigrationMatrix              `yaml:"migration_matrix"`
	DeploymentContexts map[string]DeploymentContext `yaml:"deployment_contexts"`
	Caveats          map[string]Caveat            `yaml:"caveats"`
	Mitigations      map[string]Mitigation        `yaml:"mitigations"`
}

type MigrationMatrix struct {
	KeyExchange map[string]AlgorithmMapping `yaml:"key_exchange"`
	Signatures  map[string]AlgorithmMapping `yaml:"signatures"`
	Symmetric   map[string]AlgorithmMapping `yaml:"symmetric"`
	Hashing     map[string]AlgorithmMapping `yaml:"hashing"`
}

type AlgorithmMapping struct {
	Target   string `yaml:"target"`
	UseCase  string `yaml:"use_case"`
	Priority string `yaml:"priority"`
	Timeline string `yaml:"timeline"`
}

type DeploymentContext struct {
	Description    string   `yaml:"description"`
	Caveats        []string `yaml:"caveats"`
	Mitigations    []string `yaml:"mitigations"`
	ReadinessLevel string   `yaml:"readiness_level"`
}

type Caveat struct {
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
	Impact      string `yaml:"impact"`
	Severity    string `yaml:"severity"`
}

type Mitigation struct {
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
	Effort      string `yaml:"effort"`
}

// MigrationPlan is the output structure
type MigrationPlan struct {
	Findings []MigrationFinding `json:"findings"`
	Summary  MigrationSummary   `json:"summary"`
}

type MigrationFinding struct {
	File              string   `json:"file"`
	Algorithm         string   `json:"algorithm"`
	Type              string   `json:"type"`
	Risk              string   `json:"risk"`
	TargetAlgorithm   string   `json:"target_algorithm"`
	Readiness         string   `json:"readiness"`
	Caveats           []string `json:"caveats,omitempty"`
	Mitigations       []string `json:"mitigations,omitempty"`
	Priority          string   `json:"priority"`
	Timeline          string   `json:"timeline"`
	DeploymentContext string   `json:"deployment_context,omitempty"`
}

type MigrationSummary struct {
	TotalFindings     int               `json:"total_findings"`
	ByPriority        map[string]int    `json:"by_priority"`
	ByReadiness       map[string]int    `json:"by_readiness"`
	DeploymentContext string            `json:"deployment_context,omitempty"`
	TargetTimeline    string            `json:"target_timeline,omitempty"`
}

// LoadRules loads migration rules from YAML file
func LoadRules(filepath string) (*MigrationRules, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	var rules MigrationRules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	return &rules, nil
}

// GeneratePlan generates a migration plan from scan results
func GeneratePlan(results []crypto.Result, rules *MigrationRules, context, timeline string) *MigrationPlan {
	plan := &MigrationPlan{
		Findings: make([]MigrationFinding, 0),
		Summary: MigrationSummary{
			ByPriority:        make(map[string]int),
			ByReadiness:       make(map[string]int),
			DeploymentContext: context,
			TargetTimeline:    timeline,
		},
	}

	// Get deployment context info
	var contextInfo *DeploymentContext
	if context != "" {
		if ctx, ok := rules.DeploymentContexts[context]; ok {
			contextInfo = &ctx
		}
	}

	for _, result := range results {
		finding := MigrationFinding{
			File:              result.File,
			Algorithm:         result.Algorithm,
			Type:              result.Type,
			Risk:              result.Risk,
			DeploymentContext: context,
		}

		// Find matching algorithm in migration matrix
		mapping := findAlgorithmMapping(result.Algorithm, result.Type, rules)
		if mapping != nil {
			finding.TargetAlgorithm = mapping.Target
			finding.Priority = mapping.Priority
			finding.Timeline = mapping.Timeline

			// Override timeline if user specified one
			if timeline != "" {
				finding.Timeline = timeline
			}
		} else {
			// Default values if no mapping found
			finding.TargetAlgorithm = "Unknown"
			finding.Priority = "medium"
			finding.Timeline = "2026-Q1"
		}

		// Add context-specific caveats and mitigations
		if contextInfo != nil {
			finding.Caveats = contextInfo.Caveats
			finding.Mitigations = contextInfo.Mitigations
			finding.Readiness = contextInfo.ReadinessLevel
		} else {
			finding.Readiness = "unknown"
		}

		plan.Findings = append(plan.Findings, finding)

		// Update summary counts
		plan.Summary.ByPriority[finding.Priority]++
		plan.Summary.ByReadiness[finding.Readiness]++
	}

	plan.Summary.TotalFindings = len(plan.Findings)

	return plan
}

// findAlgorithmMapping finds the migration mapping for an algorithm
func findAlgorithmMapping(algorithm, algType string, rules *MigrationRules) *AlgorithmMapping {
	algoUpper := strings.ToUpper(algorithm)

	// Try to match based on type
	switch strings.ToLower(algType) {
	case "key exchange", "key establishment":
		if mapping, ok := rules.MigrationMatrix.KeyExchange[algorithm]; ok {
			return &mapping
		}
		// Try variations
		for key, mapping := range rules.MigrationMatrix.KeyExchange {
			if strings.Contains(algoUpper, strings.ToUpper(key)) {
				return &mapping
			}
		}

	case "signature", "digital signature":
		if mapping, ok := rules.MigrationMatrix.Signatures[algorithm]; ok {
			return &mapping
		}
		for key, mapping := range rules.MigrationMatrix.Signatures {
			if strings.Contains(algoUpper, strings.ToUpper(key)) {
				return &mapping
			}
		}

	case "hash", "hashing":
		if mapping, ok := rules.MigrationMatrix.Hashing[algorithm]; ok {
			return &mapping
		}
		for key, mapping := range rules.MigrationMatrix.Hashing {
			if strings.Contains(algoUpper, strings.ToUpper(key)) {
				return &mapping
			}
		}

	case "encryption", "cipher", "symmetric":
		if mapping, ok := rules.MigrationMatrix.Symmetric[algorithm]; ok {
			return &mapping
		}
		for key, mapping := range rules.MigrationMatrix.Symmetric {
			if strings.Contains(algoUpper, strings.ToUpper(key)) {
				return &mapping
			}
		}
	}

	return nil
}

// WritePlanToFile writes the migration plan to a JSON file
func WritePlanToFile(plan *MigrationPlan, filepath string) error {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal plan: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write plan file: %w", err)
	}

	return nil
}
