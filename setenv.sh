#!/bin/bash

echo "================================================"
echo "Aqua Security Terraform Setup Script"
echo "================================================"
echo ""

# Set Aqua Security environment variables securely
echo "• Setting Aqua Security environment variables..."
export TF_VAR_aqua_url='https://cloud-dev.aquasec.com'
export TF_VAR_aqua_username='philip.pearson+slim1752154445@aquasec.com'
export TF_VAR_aqua_password='Maximise7343!'

# Display configured environment (without showing password)
echo "  ✓ TF_VAR_aqua_url set to: $TF_VAR_aqua_url"
echo "  ✓ TF_VAR_aqua_username set to: $TF_VAR_aqua_username"
echo "  ✓ TF_VAR_aqua_password set (hidden for security)"

echo ""

# Initialize Terraform
echo "• Initializing Terraform project..."
if terraform init > /dev/null 2>&1; then
    echo "  ✓ Terraform initialized successfully"

    # Show provider version
    provider_version=$(terraform version -json 2>/dev/null | grep -o '"provider_selections":.*' | grep -o '"registry.terraform.io/aquasecurity/aquasec":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$provider_version" ]; then
        echo "  ✓ Aqua provider version: $provider_version"
    fi
else
    echo "  ✗ Failed to initialize Terraform"
    echo "  Please check your Terraform installation and try again"
    exit 1
fi

echo ""
echo "================================================"
echo "Setup completed successfully!"
echo "================================================"
echo ""
echo "Import Command Reminder:"
echo "────────────────────────────────────────────────"
echo "To import resources and generate configuration:"
echo ""
echo "  terraform plan -generate-config-out=\"<filename>.tf\""
echo ""
echo "Examples:"
echo "  • terraform plan -generate-config-out=\"dora_k8.tf\""
echo "  • terraform plan -generate-config-out=\"CIS.tf\""
echo "  • terraform plan -generate-config-out=\"dora_ia.tf\""
echo ""
echo "Note: First uncomment the relevant import block in imports.tf"
echo "────────────────────────────────────────────────"
echo ""
echo "Next steps:"
echo "1. Edit imports.tf to uncomment the import block you need"
echo "2. Run: terraform plan -generate-config-out=\"<filename>.tf\""
echo "3. Review and apply the generated configuration"
echo "4. To clean up when done, run: ./cleanup.sh"
echo ""