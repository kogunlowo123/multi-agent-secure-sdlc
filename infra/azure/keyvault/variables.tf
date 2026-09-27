variable "prefix" {
  type        = string
  description = "Resource name prefix"
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

variable "aks_workload_identity_object_id" {
  type        = string
  description = "Object ID of the AKS workload identity for Key Vault access"
}

variable "allowed_ip_ranges" {
  type        = list(string)
  description = "IP ranges allowed to access Key Vault"
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default     = {}
}
