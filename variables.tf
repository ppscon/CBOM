# variable "aqua_url" {
#   description = "Aqua Security instance URL"
#   type        = string
# }
#
# variable "aqua_username" {
#   description = "Username for Aqua Security"
#   type        = string
# }
#
# variable "aqua_password" {
#   description = "Password for Aqua Security"
#   type        = string
#   sensitive   = true
# }

variable "aqua_url" {
  description = "Aqua Security instance URL"
  type        = string
  default     = "https://cloud-dev.aquasec.com"
}

variable "aqua_username" {
  description = "Username for Aqua Security"
  type        = string
  default     = "philip.pearson+slim1752154445@aquasec.com"
}

variable "aqua_password" {
  description = "Password for Aqua Security"
  type        = string
  sensitive   = true
  default     = "Maximise7343!"
}

