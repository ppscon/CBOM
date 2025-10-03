package crypto

import (
	"time"
)

// NISTCategory represents the post-quantum security categories from NIST IR 8547
type NISTCategory string

const (
	NISTCategory1          NISTCategory = "1"
	NISTCategory2          NISTCategory = "2"
	NISTCategory3          NISTCategory = "3"
	NISTCategory4          NISTCategory = "4"
	NISTCategory5          NISTCategory = "5"
	NISTCategoryDeprecated NISTCategory = "deprecated"
	NISTCategoryDisallowed NISTCategory = "disallowed"
)

// NISTTimeline represents key dates from NIST IR 8547
var (
	NISTDeprecationDate2030 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	NISTDisallowanceDate2035 = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
)

// NISTAlgorithmInfo contains NIST IR 8547 specific information for an algorithm
type NISTAlgorithmInfo struct {
	AlgorithmID      string       // e.g., "ML-KEM-512", "RSA-2048"
	Category         NISTCategory // Security category from Table 1
	DeprecationDate  *time.Time   // When algorithm becomes deprecated
	DisallowanceDate *time.Time   // When algorithm becomes disallowed
	QuantumResistant bool         // Whether algorithm resists quantum attacks
	SecurityStrength int          // Classical security strength in bits
	Table            string       // Which NIST IR 8547 table references this
}

// NISTAlgorithmMap maps algorithm identifiers to their NIST IR 8547 information
var NISTAlgorithmMap = map[string]NISTAlgorithmInfo{
	// Digital Signatures - Table 2 (Quantum-Vulnerable)
	"ECDSA-P256": {
		AlgorithmID:      "ECDSA-P256",
		Category:         NISTCategoryDeprecated,
		DeprecationDate:  &NISTDeprecationDate2030,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 128,
		Table:            "Table 2",
	},
	"ECDSA-P384": {
		AlgorithmID:      "ECDSA-P384",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 192,
		Table:            "Table 2",
	},
	"ECDSA-P521": {
		AlgorithmID:      "ECDSA-P521",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 256,
		Table:            "Table 2",
	},
	"EdDSA-Ed25519": {
		AlgorithmID:      "Ed25519",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 128,
		Table:            "Table 2",
	},
	"EdDSA-Ed448": {
		AlgorithmID:      "Ed448",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 224,
		Table:            "Table 2",
	},
	"RSA-2048": {
		AlgorithmID:      "RSA-2048",
		Category:         NISTCategoryDeprecated,
		DeprecationDate:  &NISTDeprecationDate2030,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 112,
		Table:            "Table 2",
	},
	"RSA-3072": {
		AlgorithmID:      "RSA-3072",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 128,
		Table:            "Table 2",
	},
	"RSA-4096": {
		AlgorithmID:      "RSA-4096",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 152,
		Table:            "Table 2",
	},

	// Digital Signatures - Table 3 (Post-Quantum)
	"ML-DSA-44": {
		AlgorithmID:      "ML-DSA-44",
		Category:         NISTCategory2,
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 3",
	},
	"ML-DSA-65": {
		AlgorithmID:      "ML-DSA-65",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"ML-DSA-87": {
		AlgorithmID:      "ML-DSA-87",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},
	"SLH-DSA-SHA2-128s": {
		AlgorithmID:      "SLH-DSA-SHA2-128s",
		Category:         NISTCategory1,
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 3",
	},
	"SLH-DSA-SHA2-128f": {
		AlgorithmID:      "SLH-DSA-SHA2-128f",
		Category:         NISTCategory1,
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 3",
	},
	"SLH-DSA-SHAKE-128s": {
		AlgorithmID:      "SLH-DSA-SHAKE-128s",
		Category:         NISTCategory1,
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 3",
	},
	"SLH-DSA-SHAKE-128f": {
		AlgorithmID:      "SLH-DSA-SHAKE-128f",
		Category:         NISTCategory1,
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 3",
	},
	"SLH-DSA-SHA2-192s": {
		AlgorithmID:      "SLH-DSA-SHA2-192s",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"SLH-DSA-SHA2-192f": {
		AlgorithmID:      "SLH-DSA-SHA2-192f",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"SLH-DSA-SHAKE-192s": {
		AlgorithmID:      "SLH-DSA-SHAKE-192s",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"SLH-DSA-SHAKE-192f": {
		AlgorithmID:      "SLH-DSA-SHAKE-192f",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"SLH-DSA-SHA2-256s": {
		AlgorithmID:      "SLH-DSA-SHA2-256s",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},
	"SLH-DSA-SHA2-256f": {
		AlgorithmID:      "SLH-DSA-SHA2-256f",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},
	"SLH-DSA-SHAKE-256s": {
		AlgorithmID:      "SLH-DSA-SHAKE-256s",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},
	"SLH-DSA-SHAKE-256f": {
		AlgorithmID:      "SLH-DSA-SHAKE-256f",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},

	// Stateful Hash-Based Signatures
	"LMS-SHA256-192": {
		AlgorithmID:      "LMS-SHA256/192",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"LMS-SHA256": {
		AlgorithmID:      "LMS-SHA256",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},
	"LMS-SHAKE256-192": {
		AlgorithmID:      "LMS-SHAKE256/192",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"LMS-SHAKE256": {
		AlgorithmID:      "LMS-SHAKE256",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},
	"HSS-SHA256-192": {
		AlgorithmID:      "HSS-SHA256/192",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"HSS-SHA256": {
		AlgorithmID:      "HSS-SHA256",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},
	"XMSS-SHA256-192": {
		AlgorithmID:      "XMSS-SHA256/192",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"XMSS-SHA256": {
		AlgorithmID:      "XMSS-SHA256",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},
	"XMSSMT-SHA256-192": {
		AlgorithmID:      "XMSSMT-SHA256/192",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 3",
	},
	"XMSSMT-SHA256": {
		AlgorithmID:      "XMSSMT-SHA256",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 3",
	},

	// Key Establishment - Table 4 (Quantum-Vulnerable)
	"DH-2048": {
		AlgorithmID:      "DH-2048",
		Category:         NISTCategoryDeprecated,
		DeprecationDate:  &NISTDeprecationDate2030,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 112,
		Table:            "Table 4",
	},
	"DH-3072": {
		AlgorithmID:      "DH-3072",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 128,
		Table:            "Table 4",
	},
	"ECDH-P256": {
		AlgorithmID:      "ECDH-P256",
		Category:         NISTCategoryDeprecated,
		DeprecationDate:  &NISTDeprecationDate2030,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 128,
		Table:            "Table 4",
	},
	"ECDH-P384": {
		AlgorithmID:      "ECDH-P384",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 192,
		Table:            "Table 4",
	},
	"ECDH-P521": {
		AlgorithmID:      "ECDH-P521",
		Category:         NISTCategoryDeprecated,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 256,
		Table:            "Table 4",
	},
	"MQV-2048": {
		AlgorithmID:      "MQV-2048",
		Category:         NISTCategoryDeprecated,
		DeprecationDate:  &NISTDeprecationDate2030,
		DisallowanceDate: &NISTDisallowanceDate2035,
		QuantumResistant: false,
		SecurityStrength: 112,
		Table:            "Table 4",
	},

	// Key Establishment - Table 5 (Post-Quantum)
	"ML-KEM-512": {
		AlgorithmID:      "ML-KEM-512",
		Category:         NISTCategory1,
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 5",
	},
	"ML-KEM-768": {
		AlgorithmID:      "ML-KEM-768",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 5",
	},
	"ML-KEM-1024": {
		AlgorithmID:      "ML-KEM-1024",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 5",
	},

	// Block Ciphers - Table 6
	"AES-128": {
		AlgorithmID:      "AES-128",
		Category:         NISTCategory1,
		QuantumResistant: true, // Against known quantum attacks
		SecurityStrength: 128,
		Table:            "Table 6",
	},
	"AES-192": {
		AlgorithmID:      "AES-192",
		Category:         NISTCategory3,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 6",
	},
	"AES-256": {
		AlgorithmID:      "AES-256",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 6",
	},

	// Hash Functions - Table 7
	"SHA-1": {
		AlgorithmID:      "SHA-1",
		Category:         NISTCategoryDeprecated,
		QuantumResistant: false, // Broken + inadequate quantum security
		SecurityStrength: 80,
		Table:            "Table 7",
	},
	"SHA-224": {
		AlgorithmID:      "SHA-224",
		Category:         NISTCategory1, // <1 for collision resistance
		QuantumResistant: true,
		SecurityStrength: 112,
		Table:            "Table 7",
	},
	"SHA-256": {
		AlgorithmID:      "SHA-256",
		Category:         NISTCategory2, // Category 2 for collision resistance
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 7",
	},
	"SHA-384": {
		AlgorithmID:      "SHA-384",
		Category:         NISTCategory4, // Category 4 for collision resistance
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 7",
	},
	"SHA-512": {
		AlgorithmID:      "SHA-512",
		Category:         NISTCategory5, // Category 5 for collision resistance
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 7",
	},
	"SHA3-224": {
		AlgorithmID:      "SHA3-224",
		Category:         NISTCategory1,
		QuantumResistant: true,
		SecurityStrength: 112,
		Table:            "Table 7",
	},
	"SHA3-256": {
		AlgorithmID:      "SHA3-256",
		Category:         NISTCategory2,
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 7",
	},
	"SHA3-384": {
		AlgorithmID:      "SHA3-384",
		Category:         NISTCategory4,
		QuantumResistant: true,
		SecurityStrength: 192,
		Table:            "Table 7",
	},
	"SHA3-512": {
		AlgorithmID:      "SHA3-512",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 7",
	},
	"SHAKE128": {
		AlgorithmID:      "SHAKE128",
		Category:         NISTCategory2,
		QuantumResistant: true,
		SecurityStrength: 128,
		Table:            "Table 7",
	},
	"SHAKE256": {
		AlgorithmID:      "SHAKE256",
		Category:         NISTCategory5,
		QuantumResistant: true,
		SecurityStrength: 256,
		Table:            "Table 7",
	},
}

// GetNISTInfo returns NIST IR 8547 information for an algorithm
func GetNISTInfo(algorithmName string) *NISTAlgorithmInfo {
	if info, exists := NISTAlgorithmMap[algorithmName]; exists {
		return &info
	}
	return nil
}

// IsDeprecatedByDate checks if an algorithm is deprecated based on the current date
func IsDeprecatedByDate(info *NISTAlgorithmInfo, checkDate time.Time) bool {
	if info.DeprecationDate != nil && checkDate.After(*info.DeprecationDate) {
		return true
	}
	return false
}

// IsDisallowedByDate checks if an algorithm is disallowed based on the current date
func IsDisallowedByDate(info *NISTAlgorithmInfo, checkDate time.Time) bool {
	if info.DisallowanceDate != nil && checkDate.After(*info.DisallowanceDate) {
		return true
	}
	return false
}

// GetTimelineStatus returns the timeline status of an algorithm
func GetTimelineStatus(info *NISTAlgorithmInfo, checkDate time.Time) string {
	if IsDisallowedByDate(info, checkDate) {
		return "disallowed"
	}
	if IsDeprecatedByDate(info, checkDate) {
		return "deprecated"
	}
	if info.QuantumResistant {
		return "quantum-resistant"
	}
	return "vulnerable"
}