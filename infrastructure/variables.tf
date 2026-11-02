variable "aws_region" {
  type    = string
  default = "ca-central-1"
}
variable "project_name" {
  type    = string
  default = "terraform-security-lab"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,31}$", var.project_name))
    error_message = "Use 3–32 lowercase letters, digits or hyphens, starting with a letter."
  }
}
variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
  validation {
    condition     = can(cidrsubnet(var.vpc_cidr, 8, 1)) && can(regex("^[0-9.]+/", var.vpc_cidr))
    error_message = "Provide an IPv4 CIDR large enough for two subnets with eight additional prefix bits."
  }
}
variable "enable_remediation" {
  description = "Opt in to deleting entire ingress rules that expose protected ports publicly."
  type        = bool
  default     = false
}
variable "notification_email" {
  description = "Optional SNS email subscription; recipient must confirm it."
  type        = string
  default     = ""
}
variable "protected_ports" {
  type    = list(number)
  default = [22, 3389, 3306, 5432, 6379, 27017]
  validation {
    condition     = length(var.protected_ports) > 0 && alltrue([for p in var.protected_ports : p >= 1 && p <= 65535 && floor(p) == p])
    error_message = "Supply at least one integer port between 1 and 65535."
  }
}
