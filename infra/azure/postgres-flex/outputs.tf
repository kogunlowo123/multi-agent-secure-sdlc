output "server_id" {
  description = "PostgreSQL Flex server ID"
  value       = azurerm_postgresql_flexible_server.main.id
}

output "server_fqdn" {
  description = "PostgreSQL Flex server FQDN"
  value       = azurerm_postgresql_flexible_server.main.fqdn
}

output "database_name" {
  description = "Database name"
  value       = azurerm_postgresql_flexible_server_database.secure_sdlc.name
}

output "admin_password" {
  description = "Admin password (sensitive)"
  value       = random_password.postgres_admin.result
  sensitive   = true
}
