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

variable "kubernetes_version" {
  type        = string
  description = "Kubernetes version"
  default     = "1.30"
}

variable "aks_subnet_id" {
  type        = string
  description = "AKS subnet ID"
}

variable "system_node_count" {
  type        = number
  description = "System node pool count"
  default     = 2
}

variable "system_node_vm_size" {
  type        = string
  description = "System node VM size"
  default     = "Standard_D2s_v5"
}

variable "workload_node_count" {
  type        = number
  description = "Workload node pool count"
  default     = 2
}

variable "workload_node_vm_size" {
  type        = string
  description = "Workload node VM size"
  default     = "Standard_D4s_v5"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace ID for OMS agent"
}

variable "tags" {
  type        = map(string)
  description = "Resource tags"
  default     = {}
}
