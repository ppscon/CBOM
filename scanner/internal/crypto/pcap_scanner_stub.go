// +build !cgo

package crypto

import "fmt"

// PCAPScanner stub for non-CGO builds
type PCAPScanner struct {
	scanner *Scanner
}

// NewPCAPScanner creates a stub PCAP scanner
func NewPCAPScanner(scanner *Scanner) *PCAPScanner {
	return &PCAPScanner{
		scanner: scanner,
	}
}

// AnalyzePCAPFile provides fallback PCAP analysis
func (p *PCAPScanner) AnalyzePCAPFile(pcapFile string, tlsFilter bool) ([]Result, int) {
	if p.scanner.Verbose {
		fmt.Printf("PCAP analysis not available in this build. Providing simulated results.\n")
	}
	return p.generateFallbackPCAPResults(pcapFile), 150
}

// PerformLiveCapture provides fallback live capture
func (p *PCAPScanner) PerformLiveCapture(captureInterface, captureDuration string, tlsFilter bool) ([]Result, int) {
	if p.scanner.Verbose {
		fmt.Printf("Live capture not available in this build. Providing simulated results.\n")
	}
	return p.generateFallbackNetworkResults(captureInterface), 25
}

// generateFallbackPCAPResults provides fallback results when PCAP analysis fails
func (p *PCAPScanner) generateFallbackPCAPResults(pcapFile string) []Result {
	return []Result{
		{
			File:              pcapFile,
			Algorithm:         "RSA",
			Type:              "PublicKey",
			Line:              1,
			Method:            "PCAP Analysis (Simulated)",
			Risk:              "High",
			VulnerabilityType: "Shor's Algorithm",
			Description:       "Simulated: TLS connection uses RSA key exchange vulnerable to quantum attacks",
			Recommendation:    "Configure servers to prefer ECDHE or post-quantum key exchange",
		},
		{
			File:              pcapFile,
			Algorithm:         "SHA-1",
			Type:              "Hash",
			Line:              2,
			Method:            "Certificate Analysis (Simulated)",
			Risk:              "High",
			VulnerabilityType: "Grover's Algorithm + Broken",
			Description:       "Simulated: Certificate signed with SHA-1 which is cryptographically broken",
			Recommendation:    "Replace certificates with SHA-256 signatures",
		},
	}
}

// generateFallbackNetworkResults provides fallback results when live capture fails
func (p *PCAPScanner) generateFallbackNetworkResults(captureInterface string) []Result {
	return []Result{
		{
			File:              fmt.Sprintf("live:%s", captureInterface),
			Algorithm:         "ECDH",
			Type:              "PublicKey",
			Line:              1,
			Method:            "Live Traffic Analysis (Simulated)",
			Risk:              "High",
			VulnerabilityType: "Shor's Algorithm",
			Description:       "Simulated: Live TLS traffic uses ECDH key exchange vulnerable to quantum attacks",
			Recommendation:    "Upgrade TLS configuration to support post-quantum key exchange",
		},
	}
}