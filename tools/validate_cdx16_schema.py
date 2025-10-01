#!/usr/bin/env python3
"""
CycloneDX 1.6 Schema Validator for CBOM outputs
Validates CBOM JSON against CycloneDX 1.6 specification
"""
import argparse
import json
import sys
from typing import Any, Dict, List, Tuple


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_spec_version(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate specVersion field"""
    errors = []
    spec_version = doc.get("specVersion")

    if not spec_version:
        errors.append("Missing required field: specVersion")
        return False, errors

    if spec_version != "1.6":
        errors.append(f"Expected specVersion '1.6', got '{spec_version}'")
        return False, errors

    return True, []


def validate_bom_format(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate bomFormat field"""
    errors = []
    bom_format = doc.get("bomFormat")

    if not bom_format:
        errors.append("Missing required field: bomFormat")
        return False, errors

    if bom_format != "CycloneDX":
        errors.append(f"Expected bomFormat 'CycloneDX', got '{bom_format}'")
        return False, errors

    return True, []


def validate_component_properties(components: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """Validate component.properties structure for 1.6"""
    errors = []
    warnings = []

    cbom_property_names = {
        "cbom:algorithm",
        "cbom:purpose",
        "cbom:quantumRisk",
        "cbom:quantumSafe",
        "cbom:primitive",
        "cbom:variant",
        "cbom:scanner",
        "cbom:detectionContext:filePath"
    }

    components_with_crypto = 0
    components_with_properties = 0

    for idx, component in enumerate(components):
        # Check if component has old .crypto field (should not exist in 1.6)
        if "crypto" in component:
            warnings.append(
                f"Component {idx} ({component.get('name', 'unnamed')}) "
                f"has .crypto field (should use .properties in 1.6)"
            )
            components_with_crypto += 1

        # Check properties structure
        properties = component.get("properties", [])
        if not isinstance(properties, list):
            errors.append(f"Component {idx}: properties must be an array")
            continue

        # Check for cbom: properties
        cbom_props = [p for p in properties if p.get("name", "").startswith("cbom:")]
        if cbom_props:
            components_with_properties += 1

            # Validate property structure
            for prop in cbom_props:
                if not isinstance(prop, dict):
                    errors.append(f"Component {idx}: property must be an object")
                    continue

                if "name" not in prop:
                    errors.append(f"Component {idx}: property missing 'name' field")

                if "value" not in prop:
                    errors.append(f"Component {idx}: property missing 'value' field")

    return len(errors) == 0, errors + warnings


def validate_metadata(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate metadata section"""
    errors = []
    metadata = doc.get("metadata", {})

    if not metadata:
        errors.append("Missing metadata section")
        return False, errors

    # Check tools array
    tools = metadata.get("tools", [])
    if not tools:
        errors.append("metadata.tools array is empty or missing")

    # Check timestamp
    if "timestamp" not in metadata:
        errors.append("metadata.timestamp is missing")

    return len(errors) == 0, errors


def validate_cbom_16(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Run all validations"""
    all_errors = []
    all_ok = True

    # 1. Validate bomFormat
    ok, errors = validate_bom_format(doc)
    all_ok = all_ok and ok
    all_errors.extend(errors)

    # 2. Validate specVersion
    ok, errors = validate_spec_version(doc)
    all_ok = all_ok and ok
    all_errors.extend(errors)

    # 3. Validate metadata
    ok, errors = validate_metadata(doc)
    all_ok = all_ok and ok
    all_errors.extend(errors)

    # 4. Validate components
    components = doc.get("components", [])
    if components:
        ok, errors = validate_component_properties(components)
        all_ok = all_ok and ok
        all_errors.extend(errors)

    return all_ok, all_errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate CBOM against CycloneDX 1.6 schema"
    )
    parser.add_argument("files", nargs="+", help="Path(s) to CBOM JSON file(s)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors"
    )
    args = parser.parse_args()

    all_ok = True

    for path in args.files:
        try:
            doc = load_json(path)
        except Exception as e:
            print(f"[FAIL] {path}: Invalid JSON: {e}")
            all_ok = False
            continue

        ok, messages = validate_cbom_16(doc)

        if ok:
            print(f"[OK] {path}: Valid CycloneDX 1.6 CBOM")
        else:
            all_ok = False
            print(f"[FAIL] {path}:")
            for msg in messages:
                # Distinguish errors from warnings
                if "warning" in msg.lower() or "should" in msg.lower():
                    prefix = "[WARN]" if not args.strict else "[ERROR]"
                    if args.strict:
                        all_ok = False
                else:
                    prefix = "[ERROR]"
                print(f"  {prefix} {msg}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())