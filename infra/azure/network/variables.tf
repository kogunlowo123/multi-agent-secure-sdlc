variable "prefix" {
  type        = string
  description = "Resource name prefix"
}

variable "location" {
  type        = string
  description = "Azure region"
  default     = "eastus"
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

variable "vnet_address_space" {
  type        = list(string)
  description = "VNet address space"
  default     = ["10.0.0.0/16"]
}

variable "aks_subnet_cidr" {
  type        = string
  description = "AKS subnet CIDR"
  default     = "10.0.1.0/24"
}

variable "postgres_subnet_cidr" {
  type        = string
  description = "PostgreSQL subnet CIDR"
  default     = "10.0.2.0/24"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default     = {}
}
