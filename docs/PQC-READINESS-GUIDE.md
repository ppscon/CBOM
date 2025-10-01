# Post-Quantum Cryptography (PQC) Readiness Guide

## Executive Summary

FIPS 140-3's forward-looking provisions for post-quantum cryptography (PQC) represent a critical advantage for organizations planning for quantum computing threats. This guide explains how Aqua-CBOM positions your organization ahead of the curve.

---

## Why PQC Matters for FIPS 140-3

### The Quantum Threat Timeline

**Current State** (2025):
- Quantum computers exist but lack cryptographic attack capability
- RSA-2048, ECDSA-P256 remain FIPS-approved and secure
- Organizations have time to plan migration

**Near Future** (2025-2030):
- NIST completing PQC algorithm standardization
- First PQC algorithms added to FIPS 140-3 approved list
- Early adopters begin hybrid classical+PQC implementations

**Long-term** (2030-2040):
- Cryptographically-relevant quantum computers emerge
- Classical algorithms (RSA, ECC) become vulnerable
- PQC becomes mandatory for sensitive systems

### FIPS 140-3's PQC Advantage

**FIPS 140-2** (Legacy):
- ❌ No provisions for post-quantum algorithms
- ❌ Would require new standard revision for PQC
- ❌ Organizations stuck with classical algorithms until 140-2 replacement

**FIPS 140-3** (Current):
- ✅ Explicitly designed to accommodate future PQC algorithms
- ✅ Framework ready for NIST PQC standards integration
- ✅ Organizations can plan migration while maintaining 140-3 compliance
- ✅ Smooth transition path as NIST approves algorithms

**Key Insight**: FIPS 140-3 won't need replacement when PQC arrives - it's already structured to accept them.

---

## NIST Post-Quantum Cryptography Standardization

### Current Status (2025)

**NIST PQC Standards**:
1. **FIPS 203**: ML-KEM (Module-Lattice-Based Key Encapsulation)
   - Replaces: RSA and ECDH for key exchange
   - Status: Final standard published August 2024

2. **FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature)
   - Replaces: RSA and ECDSA for digital signatures
   - Status: Final standard published August 2024

3. **FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature)
   - Replaces: RSA and ECDSA (alternative approach)
   - Status: Final standard published August 2024

**Additional Candidates** (Under Evaluation):
- BIKE, HQC, Classic McEliece (code-based)
- SPHINCS+ variants
- Additional lattice-based schemes

### Integration Timeline

| Timeframe | Milestone |
|-----------|-----------|
| **2024 Q3** | NIST publishes first 3 PQC standards |
| **2025-2026** | Vendors implement PQC in cryptographic modules |
| **2026-2027** | First FIPS 140-3 modules with PQC validated by CMVP |
| **2027-2030** | Hybrid classical+PQC becomes common |
| **2030+** | PQC-only implementations for high-security systems |

---

## How Aqua-CBOM Enables PQC Readiness

### 1. Current Cryptographic Inventory

**Capability**: Aqua-CBOM identifies all cryptographic algorithms in use today.

**Value for PQC Planning**:
```json
{
  "component": "/app/lib/auth.js",
  "crypto": {
    "algorithm": "RSA-2048",
    "purpose": "Signature",
    "quantumSafe": false,
    "quantumRisk": "Shor's Algorithm"
  }
}
```

**Strategic Insight**:
- **Know what needs replacement**: RSA-2048 signatures → ML-DSA (FIPS 204)
- **Prioritize by risk**: High-value systems first
- **Plan budget**: Understand scope of migration

**Example Planning Matrix**:
| Component | Current Algorithm | Quantum-Vulnerable? | PQC Replacement | Priority |
|-----------|-------------------|---------------------|-----------------|----------|
| API Auth | RSA-2048 | ✅ Yes | ML-DSA (FIPS 204) | High |
| TLS Key Exchange | ECDH-P256 | ✅ Yes | ML-KEM (FIPS 203) | High |
| Data Encryption | AES-256 | ⚠️ Partial (Grover's) | AES-256 (sufficient) | Low |
| Hashing | SHA-256 | ⚠️ Partial (Grover's) | SHA-256 (sufficient) | Low |

### 2. Quantum Risk Assessment

**Capability**: Aqua-CBOM provides NIST-based quantum vulnerability analysis.

**Risk Levels**:
- **Critical**: RSA-1024, ECC-P192 (already weak + quantum-vulnerable)
- **High**: RSA-2048, RSA-3072, ECDSA-P256 (secure now, quantum-vulnerable)
- **Medium**: RSA-4096, ECDSA-P384, ECDSA-P521 (longer runway before quantum threat)
- **Low**: AES-128, SHA-256 (Grover's algorithm halves security, but still adequate with key size increase)

**Example CBOM Output**:
```json
{
  "summary": {
    "total_assets": 47,
    "quantum_safe_assets": 12,
    "quantum_vulnerable_assets": 35,
    "critical_risk_assets": 3,
    "high_risk_assets": 18,
    "medium_risk_assets": 14
  },
  "findings": [
    {
      "file": "/app/auth/jwt.js",
      "algorithm": "RSA-2048",
      "risk": "High",
      "quantumRisk": "Shor's Algorithm - vulnerable to quantum cryptanalysis",
      "recommendation": "Migrate to ML-DSA (FIPS 204) for quantum resistance"
    }
  ]
}
```

**Strategic Action**: Use risk scores to prioritize migration efforts and budget allocation.

### 3. Migration Planning Support

**Capability**: CBOM provides detailed component-level inventory for migration planning.

**Migration Workflow**:

```
Phase 1: Discovery (NOW)
├── Generate CBOM for all production systems
├── Identify quantum-vulnerable algorithms
└── Assess business risk of each component

Phase 2: Pilot (2026-2027)
├── Select low-risk system for PQC pilot
├── Implement hybrid classical+PQC
└── Validate performance and compatibility

Phase 3: Progressive Rollout (2027-2030)
├── High-risk systems first
├── Medium-risk systems next
└── Low-risk systems last

Phase 4: PQC-Only (2030+)
├── Disable classical algorithms
└── Full quantum-safe infrastructure
```

**Example Migration Plan**:
```bash
# Generate CBOM for current system
./aqua-cbom-darwin -mode file -dir /app -output-cbom > current-cbom.json

# Identify quantum-vulnerable components
jq '.findings[] | select(.quantumRisk != "None")' current-cbom.json > migration-candidates.json

# Prioritize by risk and business impact
jq 'group_by(.risk) | map({risk: .[0].risk, count: length, components: map(.file)})' migration-candidates.json

# Output: Prioritized migration list
[
  {
    "risk": "High",
    "count": 18,
    "components": ["/app/auth/jwt.js", "/app/crypto/sign.js", ...]
  },
  {
    "risk": "Medium",
    "count": 14,
    "components": [...]
  }
]
```

### 4. Continuous Monitoring

**Capability**: CBOM generation in CI/CD tracks cryptographic drift over time.

**Value**:
- **Prevent regression**: Ensure new code doesn't introduce quantum-vulnerable algorithms
- **Track progress**: Monitor PQC migration completion percentage
- **Maintain compliance**: Verify FIPS 140-3 compliance throughout transition

**CI/CD Integration**:
```yaml
# .github/workflows/pqc-monitoring.yml
- name: Generate CBOM
  run: docker run enhanced-scanner --CBOM image $IMAGE

- name: Check quantum-vulnerable algorithms
  run: |
    VULN_COUNT=$(jq '[.findings[] | select(.quantumRisk != "None")] | length' cbom.json)
    echo "Quantum-vulnerable components: $VULN_COUNT"

    # Track progress over time
    echo "$VULN_COUNT" >> metrics/quantum-vuln-trend.txt

    # Fail if new vulnerabilities introduced
    if [ $VULN_COUNT -gt $BASELINE ]; then
      echo "ERROR: New quantum-vulnerable algorithms detected"
      exit 1
    fi
```

---

## Competitive Advantage

### Why Aqua-CBOM + FIPS 140-3 = Market Leadership

| Capability | Aqua-CBOM | Competitor Solutions |
|------------|----------|---------------------|
| **Current Inventory** | ✅ Complete crypto asset discovery | ⚠️ Manual audits |
| **Quantum Risk** | ✅ NIST-based risk assessment | ❌ Not addressed |
| **PQC Planning** | ✅ Component-level migration plan | ❌ Generic guidance |
| **140-3 Alignment** | ✅ Native support | ⚠️ Still on 140-2 |
| **Continuous Monitoring** | ✅ CI/CD integrated | ❌ Point-in-time |

### Customer Value Proposition

**For Defense/Aerospace (iBASET example)**:
- **Compliance Today**: FIPS 140-3 compliant now (ahead of 2026 deadline)
- **Readiness Tomorrow**: PQC migration plan in place before competitors
- **Contract Advantage**: Demonstrate quantum-safe roadmap to government clients
- **Cost Avoidance**: Plan migration over 5 years vs emergency scramble

**ROI Calculation**:
```
Without Aqua-CBOM PQC Planning:
├── Emergency migration in 2030: $2M-5M
├── Downtime during migration: $500K-1M
├── Compliance violations: $1M-10M
└── TOTAL: $3.5M-16M

With Aqua-CBOM PQC Planning:
├── Gradual migration 2026-2030: $1M-2M
├── No downtime (hybrid approach): $0
├── Continuous compliance: $0
└── TOTAL: $1M-2M

NET SAVINGS: $2.5M-14M
```

---

## Implementation Roadmap

### Phase 1: Baseline (Now - 2026)

**Objective**: Establish quantum vulnerability baseline

**Actions**:
1. Generate CBOM for all production systems
2. Identify quantum-vulnerable components
3. Assess business risk and prioritize
4. Establish PQC migration budget

**Deliverables**:
- Complete cryptographic inventory
- Quantum risk assessment report
- 5-year PQC migration plan
- Executive presentation on quantum threat

### Phase 2: Pilot (2026-2027)

**Objective**: Validate PQC implementation in low-risk system

**Actions**:
1. Select pilot system (non-critical, well-understood)
2. Implement hybrid classical+PQC (e.g., RSA-2048 + ML-DSA)
3. Test performance, compatibility, interoperability
4. Document lessons learned

**Deliverables**:
- Working hybrid cryptography system
- Performance benchmarks
- Compatibility matrix
- Updated migration plan

### Phase 3: Rollout (2027-2030)

**Objective**: Migrate high-value systems to PQC

**Actions**:
1. High-risk systems (customer-facing auth, financial transactions)
2. Medium-risk systems (internal APIs, data encryption)
3. Low-risk systems (logging, non-sensitive operations)

**Deliverables**:
- 50% PQC coverage by 2028
- 90% PQC coverage by 2030
- Updated CBOM showing progress

### Phase 4: PQC-Only (2030+)

**Objective**: Complete quantum-safe infrastructure

**Actions**:
1. Disable classical-only algorithms
2. Full PQC-only implementations
3. Continuous monitoring for new threats

**Deliverables**:
- 100% quantum-safe infrastructure
- FIPS 140-3 compliant with PQC algorithms
- Industry leadership position

---

## Best Practices

### DO

✅ **Start planning now** - Don't wait for quantum computers
✅ **Generate CBOM regularly** - Track cryptographic drift
✅ **Use risk-based prioritization** - High-value systems first
✅ **Implement hybrid crypto** - Classical+PQC during transition
✅ **Test thoroughly** - PQC algorithms have different performance characteristics
✅ **Monitor NIST standards** - Stay current with PQC developments
✅ **Document migration** - Maintain compliance evidence

### DON'T

❌ **Don't ignore quantum threat** - "Harvest now, decrypt later" attacks are real
❌ **Don't wait for quantum computers** - Migration takes 5-10 years
❌ **Don't migrate everything at once** - Phased approach reduces risk
❌ **Don't use non-NIST PQC** - Only FIPS-approved algorithms for compliance
❌ **Don't break interoperability** - Maintain compatibility during transition

---

## Conclusion

### Why Aqua-CBOM + FIPS 140-3 = PQC Leadership

**Strategic Advantages**:
1. **Complete Visibility**: Know exactly what needs migrating
2. **Risk-Based Planning**: Prioritize by business impact
3. **Continuous Monitoring**: Track progress and prevent regression
4. **FIPS 140-3 Aligned**: Future-proof compliance framework
5. **Cost Efficient**: Plan migration vs emergency response

**Market Position**:
- ✅ FIPS 140-3 compliant today
- ✅ PQC ready tomorrow
- ✅ Quantum-safe in the future

**Customer Message**:
*"While competitors scramble to understand their quantum risk in 2030, you'll have completed a planned, tested, and compliant migration - because you started with Aqua-CBOM and FIPS 140-3 in 2025."*

---

**Next Steps**:
1. Generate your first CBOM: `./aqua-cbom-darwin -mode file -dir /app -output-cbom`
2. Review quantum-vulnerable assets
3. Schedule PQC planning workshop
4. Present roadmap to leadership

*The quantum threat is real. The time to prepare is now.*
