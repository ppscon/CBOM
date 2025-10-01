terraform {
  required_providers {
    aquasec = {
      version = "0.10.0"
      source  = "aquasecurity/aquasec"
    }
  }
}

provider "aquasec" {
  aqua_url = var.aqua_url
  username = var.aqua_username
  password = var.aqua_password
}
