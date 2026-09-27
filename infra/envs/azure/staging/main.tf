terraform {
  required_version = ">= 1.8.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }

  backend "azurerm" {
    resource_group_name  = "tfstate-rg"
    storage_account_name = "sdlctfstatestg"
    container_name       = "tfstate"
    key                  = "staging.terraform.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

locals {
  prefix   = "sdlc-staging"
  location = "eastus"
  tags = {
    environment = "staging"
    project     = "multi-agent-secure-sdlc"
    managed_by  = "terraform"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "${local.prefix}-rg"
  location = local.location
  tags     = local.tags
}

module "network" {
  source = "../../azure/network"

  prefix              = local.prefix
  location            = local.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

module "postgres" {
  source = "../../azure/postgres-flex"

  prefix              = local.prefix
  location            = local.location
  resource_group_name = azurerm_resource_group.main.name
  postgres_subnet_id  = module.network.postgres_subnet_id
  vnet_id             = module.network.vnet_id
  tags                = local.tags
}
