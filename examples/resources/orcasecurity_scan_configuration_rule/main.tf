terraform {
  required_providers {
    orcasecurity = {
      source = "orcasecurity/orcasecurity"
    }
  }
}

provider "orcasecurity" {}

resource "orcasecurity_scan_configuration_rule" "managed_db_do_not_scan" {
  rule_name       = "Des test tf provider"
  rule_priority   = 21
  is_enabled_rule = false
  is_default_rule = false

  feature = "Managed DB Scanning"
  action  = "do_not_scan"

  selector_cloud_accounts = var.orca_cloud_account_ids
  selector_business_units = []

  tags     = []
  policies = []

  advanced_settings_json = jsonencode({
    managed_db_services = {
      aws       = ["redshift", "rds", "dynamodb"]
      gcp       = ["cloudsql", "bigquery"]
      azure     = ["azure_sql_db"]
      snowflake = ["snowflake"]
    }
  })
}

