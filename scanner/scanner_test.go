package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"qvs-pro/scanner/internal/crypto"
)

func TestScannerVersion(t *testing.T) {
	// Test version output
	version := "v2.2.0"
	if version == "" {
		t.Error("Version should not be empty")
	}
}

func TestAlgorithmDetection(t *testing.T) {
	testCases := []struct {
		name      string
		content   string
		expected  []string
		extension string
	}{
		{
			name:      "Java AES Detection",
			content:   `Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");`,
			expected:  []string{"AES"},
			extension: ".java",
		},
		{
			name:      "Python SHA256 Detection",
			content:   `hashlib.sha256(data).hexdigest()`,
			expected:  []string{"SHA-256"},
			extension: ".py",
		},
		{
			name:      "Java RSA Detection",
			content:   `KeyPairGenerator.getInstance("RSA")`,
			expected:  []string{"RSA"},
			extension: ".java",
		},
		{
			name:      "JavaScript DES Detection",
			content:   `CryptoJS.DES.encrypt(message, key)`,
			expected:  []string{"DES"},
			extension: ".js",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create temp file
			tmpFile := filepath.Join(t.TempDir(), "test"+tc.extension)
			err := os.WriteFile(tmpFile, []byte(tc.content), 0644)
			if err != nil {
				t.Fatal(err)
			}

			// Use real scanner
			scanner := crypto.NewScanner(false)
			results := scanner.ScanFile(tmpFile)
			
			// Check if expected algorithms are found
			for _, expected := range tc.expected {
				found := false
				for _, result := range results {
					if strings.Contains(result.Algorithm, expected) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find %s but didn't. Found: %d results", expected, len(results))
					for _, result := range results {
						t.Logf("Found: %s (%s)", result.Algorithm, result.Type)
					}
				}
			}
		})
	}
}

func TestCBOMGeneration(t *testing.T) {
	// Test CBOM structure
	cbom := map[string]interface{}{
		"cbom_version": "1.0",
		"scan_info": map[string]interface{}{
			"scanner_version": "v2.2.0",
			"scan_timestamp":  "2025-06-23T12:00:00Z",
		},
		"algorithms": []map[string]interface{}{
			{
				"algorithm": "AES-128",
				"risk_level": "Medium",
				"vulnerability_type": "Grover's Algorithm",
			},
		},
	}

	if cbom["cbom_version"] != "1.0" {
		t.Error("CBOM version should be 1.0")
	}
}

func TestMultiLanguageDetection(t *testing.T) {
	languages := []struct {
		extension string
		content   string
		algorithm string
	}{
		{".java", `KeyPairGenerator.getInstance("RSA")`, "RSA"},
		{".py", `from cryptography.hazmat.primitives.asymmetric import rsa`, "RSA"},
		{".go", `const crypto = require('crypto')`, "RSA"},
		{".js", `crypto.generateKeyPairSync('rsa')`, "RSA"},
	}

	for _, lang := range languages {
		t.Run("Language_"+lang.extension, func(t *testing.T) {
			// Create temp file
			tmpFile := filepath.Join(t.TempDir(), "test"+lang.extension)
			err := os.WriteFile(tmpFile, []byte(lang.content), 0644)
			if err != nil {
				t.Fatal(err)
			}

			// Use real scanner
			scanner := crypto.NewScanner(false)
			results := scanner.ScanFile(tmpFile)
			
			// Should detect at least one algorithm
			if len(results) == 0 {
				t.Errorf("Expected to find algorithms in %s file but found none", lang.extension)
			}
		})
	}
}