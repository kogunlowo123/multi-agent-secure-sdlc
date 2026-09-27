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

variable "postgres_subnet_id" {
  type        = string
  description = "PostgreSQL delegated subnet ID"
}

variable "vnet_id" {
  type        = string
  description = "Virtual network ID for private DNS link"
}

variable "admin_username" {
  type        = string
  description = "PostgreSQL admin username"
  default     = "sdlc_admin"
}

variable "storage_mb" {
  type        = number
  description = "Storage in MB"
  default     = 32768
}

variable "sku_name" {
  type        = string
  description = "PostgreSQL Flex SKU"
  default     = "GP_Standard_D4s_v3"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default     = {}
}
