#!/bin/bash

# Cleanup script for Aqua Security Terraform demo
# This script removes all Terraform state and generated files to ensure a clean, repeatable demo

echo "================================================"
echo "Aqua Security Terraform Demo Cleanup Script"
echo "================================================"
echo ""

# Confirm with user before proceeding
read -p "This will remove all Terraform state and generated files. Continue? (y/N): " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 0
fi

echo ""
echo "Starting cleanup..."
echo ""

# Remove Terraform state files
echo "• Removing Terraform state files..."
rm -f terraform.tfstate 2>/dev/null
rm -f terraform.tfstate.backup 2>/dev/null
rm -f terraform.tfstate.*.backup 2>/dev/null
rm -f *.tfstate 2>/dev/null
rm -f *.tfstate.* 2>/dev/null

# Remove Terraform lock file (will be regenerated on init)
echo "• Removing Terraform lock file..."
rm -f .terraform.lock.hcl 2>/dev/null

# Remove Terraform plan files
echo "• Removing Terraform plan files..."
rm -f *.tfplan 2>/dev/null
rm -f plan.tfplan 2>/dev/null

# Remove any generated configuration files from import
echo "• Checking for import-generated configuration files..."

# List of import-generated files to check
import_files=(
    "CIS.tf"
    "dora_k8.tf"
    "dora_ia.tf"
    "complianceIA.tf"
    "newpolicy.tf"
    "current_state.tf"
)

# Check if any import-generated files exist
found_files=()
for file in "${import_files[@]}"; do
    if [ -f "$file" ]; then
        found_files+=("$file")
    fi
done

# If import files found, ask for confirmation to delete
if [ ${#found_files[@]} -gt 0 ]; then
    echo "  Found import-generated files:"
    for file in "${found_files[@]}"; do
        echo "    - $file"
    done
    read -p "  Remove these import-generated .tf files? (y/N): " remove_imports
    if [[ "$remove_imports" =~ ^[Yy]$ ]]; then
        for file in "${found_files[@]}"; do
            rm -f "$file" 2>/dev/null
            echo "    ✓ Removed $file"
        done
    else
        echo "  • Keeping import-generated .tf files"
    fi
else
    echo "  • No import-generated files found"
fi

# Always remove state.json
rm -f state.json 2>/dev/null

# Clear demo imports from imports.tf
echo "• Clearing demo imports from imports.tf..."
if [ -f imports.tf ]; then
    # Create empty imports.tf with just a comment header
    cat > imports.tf << 'EOF'
# Import blocks for demo - uncomment as needed

# Runtime policy - CIS exists by default in Aqua
# import {
#   to = aquasec_container_runtime_policy.CIS
#   id = "CIS"
# }

# Kubernetes assurance policy - create dora_k8 in Aqua first
# import {
#   to = aquasec_kubernetes_assurance_policy.dora_k8
#   id = "dora_k8"
# }

# Image assurance policy - create dora_ia in Aqua first
# import {
#   to = aquasec_image_assurance_policy.dora_ia
#   id = "dora_ia"
# }
EOF
    echo "  ✓ imports.tf reset to default (all imports commented out)"
else
    echo "  ! imports.tf not found"
fi

# Remove crash log files
echo "• Removing crash log files..."
rm -f crash.log 2>/dev/null
rm -f crash.*.log 2>/dev/null

# Optional: Remove .terraform directory (will require re-init)
read -p "Remove .terraform directory (will require 'terraform init')? (y/N): " remove_terraform
if [[ "$remove_terraform" =~ ^[Yy]$ ]]; then
    echo "• Removing .terraform directory..."
    rm -rf .terraform 2>/dev/null
    rm -rf .terraform.d 2>/dev/null
else
    echo "• Keeping .terraform directory"
fi

echo ""
echo "================================================"
echo "Cleanup completed successfully!"
echo "================================================"
echo ""
echo "Next steps:"
echo "1. Run 'terraform init' to initialize the provider"
echo "2. Follow the demo steps in docs/demo.md"
echo ""