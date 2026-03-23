use super::traits::{Tool, ToolResult};
use crate::security::{policy::ToolOperation, SecurityPolicy};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

const MAX_ERROR_BODY_CHARS: usize = 500;

/// Validates that a UUID or identifier is safe for URL interpolation.
/// Prevents path traversal attacks (e.g. `../../admin`) by rejecting
/// values containing `/`, `\`, `..`, or control characters.
fn validate_path_segment(value: &str, param_name: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{param_name} cannot be empty");
    }
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.chars().any(|c| c.is_control())
    {
        anyhow::bail!(
            "Invalid {param_name} '{value}': contains forbidden characters (/, \\, .., or control chars)"
        );
    }
    Ok(())
}

/// Tool for interacting with the Coolify API v1.
///
/// Provides full cluster management: projects, environments, applications,
/// services, databases, servers, and deployments.
///
/// ## Safety
///
/// - **Protected environments**: environments listed in `protected_environments`
///   config (e.g. `["production"]`) are blocked from all mutating operations
///   (deploy, stop, restart, delete, update, env var changes).
///   Read-only actions (list, get, logs) always work.
///
/// - **Allowed actions**: like the Jira tool, only actions listed in
///   `allowed_actions` config can be called. Defaults to read-only.
///
/// - **Security policy**: mutations require `ToolOperation::Act`; reads
///   require `ToolOperation::Read`.
pub struct CoolifyTool {
    base_url: String,
    api_key: String,
    allowed_actions: HashSet<String>,
    protected_environments: HashSet<String>,
    http: Client,
    security: Arc<SecurityPolicy>,
    timeout_secs: u64,
}

impl CoolifyTool {
    pub fn new(
        base_url: String,
        api_key: String,
        allowed_actions: Vec<String>,
        protected_environments: Vec<String>,
        security: Arc<SecurityPolicy>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            allowed_actions: allowed_actions.into_iter().collect(),
            protected_environments: protected_environments
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            http: Client::new(),
            security,
            timeout_secs,
        }
    }

    fn is_action_allowed(&self, action: &str) -> bool {
        self.allowed_actions.contains(action)
    }

    /// Check whether the given environment name is protected from mutations.
    fn is_environment_protected(&self, env_name: &str) -> bool {
        self.protected_environments
            .contains(&env_name.to_lowercase())
    }

    /// Build an authenticated GET request.
    async fn api_get(&self, path: &str) -> anyhow::Result<Value> {
        let url = format!("{}/api/v1{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Coolify GET {path} request failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let truncated = crate::util::truncate_with_ellipsis(&text, MAX_ERROR_BODY_CHARS);
            anyhow::bail!("Coolify GET {path} failed ({status}): {truncated}");
        }
        resp.json().await.map_err(Into::into)
    }

    /// Build an authenticated POST request with optional JSON body.
    async fn api_post(&self, path: &str, body: Option<&Value>) -> anyhow::Result<Value> {
        let url = format!("{}/api/v1{}", self.base_url, path);
        let mut req = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .timeout(std::time::Duration::from_secs(self.timeout_secs));

        if let Some(b) = body {
            req = req.json(b); // .json() sets Content-Type automatically
        }

        let resp = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Coolify POST {path} request failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let truncated = crate::util::truncate_with_ellipsis(&text, MAX_ERROR_BODY_CHARS);
            anyhow::bail!("Coolify POST {path} failed ({status}): {truncated}");
        }
        resp.json().await.map_err(Into::into)
    }

    /// Build an authenticated PATCH request.
    async fn api_patch(&self, path: &str, body: &Value) -> anyhow::Result<Value> {
        let url = format!("{}/api/v1{}", self.base_url, path);
        let resp = self
            .http
            .patch(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(body)
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Coolify PATCH {path} request failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let truncated = crate::util::truncate_with_ellipsis(&text, MAX_ERROR_BODY_CHARS);
            anyhow::bail!("Coolify PATCH {path} failed ({status}): {truncated}");
        }
        resp.json().await.map_err(Into::into)
    }

    /// Build an authenticated DELETE request.
    async fn api_delete(&self, path: &str) -> anyhow::Result<Value> {
        let url = format!("{}/api/v1{}", self.base_url, path);
        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Coolify DELETE {path} request failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let truncated = crate::util::truncate_with_ellipsis(&text, MAX_ERROR_BODY_CHARS);
            anyhow::bail!("Coolify DELETE {path} failed ({status}): {truncated}");
        }
        // DELETE may return empty body
        let text = resp.text().await.unwrap_or_default();
        if text.is_empty() {
            Ok(json!({"deleted": true}))
        } else {
            serde_json::from_str(&text)
                .unwrap_or_else(|_| json!({"deleted": true, "response": text}))
        }
    }

    // ── Action handlers ────────────────────────────────────────────────

    // Projects
    async fn list_projects(&self) -> anyhow::Result<Value> {
        let raw = self.api_get("/projects").await?;
        Ok(shape_project_list(&raw))
    }

    async fn get_project(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/projects/{uuid}")).await
    }

    // Environments
    async fn list_environments(&self, project_uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/projects/{project_uuid}/environments"))
            .await
    }

    async fn get_environment(
        &self,
        project_uuid: &str,
        environment: &str,
    ) -> anyhow::Result<Value> {
        self.api_get(&format!("/projects/{project_uuid}/{environment}"))
            .await
    }

    // Applications
    async fn list_applications(&self) -> anyhow::Result<Value> {
        let raw = self.api_get("/applications").await?;
        Ok(shape_application_list(&raw))
    }

    async fn get_application(&self, uuid: &str) -> anyhow::Result<Value> {
        let raw = self.api_get(&format!("/applications/{uuid}")).await?;
        Ok(shape_application(&raw))
    }

    async fn deploy_application(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/applications/{uuid}/start"), None)
            .await
    }

    async fn stop_application(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/applications/{uuid}/stop"), None)
            .await
    }

    async fn restart_application(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/applications/{uuid}/restart"), None)
            .await
    }

    async fn get_application_logs(
        &self,
        uuid: &str,
        lines: Option<u32>,
    ) -> anyhow::Result<Value> {
        let lines = lines.unwrap_or(100).clamp(1, 1000);
        self.api_get(&format!("/applications/{uuid}/logs?lines={lines}"))
            .await
    }

    async fn update_application(&self, uuid: &str, data: &Value) -> anyhow::Result<Value> {
        self.api_patch(&format!("/applications/{uuid}"), data).await
    }

    // Services
    async fn list_services(&self) -> anyhow::Result<Value> {
        let raw = self.api_get("/services").await?;
        Ok(shape_service_list(&raw))
    }

    async fn get_service(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/services/{uuid}")).await
    }

    async fn start_service(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/services/{uuid}/start"), None)
            .await
    }

    async fn stop_service(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/services/{uuid}/stop"), None).await
    }

    async fn restart_service(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/services/{uuid}/restart"), None)
            .await
    }

    // Databases
    async fn list_databases(&self) -> anyhow::Result<Value> {
        let raw = self.api_get("/databases").await?;
        Ok(shape_database_list(&raw))
    }

    async fn get_database(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/databases/{uuid}")).await
    }

    async fn start_database(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/databases/{uuid}/start"), None)
            .await
    }

    async fn stop_database(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/databases/{uuid}/stop"), None)
            .await
    }

    async fn restart_database(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/databases/{uuid}/restart"), None)
            .await
    }

    // Database backups
    async fn list_backups(&self, db_uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/databases/{db_uuid}/backups")).await
    }

    async fn create_backup(
        &self,
        db_uuid: &str,
        data: &Value,
    ) -> anyhow::Result<Value> {
        self.api_post(&format!("/databases/{db_uuid}/backups"), Some(data))
            .await
    }

    async fn get_backup(
        &self,
        db_uuid: &str,
        backup_uuid: &str,
    ) -> anyhow::Result<Value> {
        // Coolify doesn't have a single-backup GET, but we can filter from the list.
        // Use the update endpoint path pattern for consistency.
        let backups = self.api_get(&format!("/databases/{db_uuid}/backups")).await?;
        if let Some(arr) = backups.as_array() {
            if let Some(found) = arr.iter().find(|b| {
                b.get("uuid")
                    .and_then(|u| u.as_str())
                    .map(|u| u == backup_uuid)
                    .unwrap_or(false)
            }) {
                return Ok(found.clone());
            }
        }
        anyhow::bail!("Backup {backup_uuid} not found for database {db_uuid}")
    }

    async fn delete_backup(
        &self,
        db_uuid: &str,
        backup_uuid: &str,
    ) -> anyhow::Result<Value> {
        self.api_delete(&format!("/databases/{db_uuid}/backups/{backup_uuid}"))
            .await
    }

    async fn list_backup_executions(
        &self,
        db_uuid: &str,
        backup_uuid: &str,
    ) -> anyhow::Result<Value> {
        self.api_get(&format!(
            "/databases/{db_uuid}/backups/{backup_uuid}/executions"
        ))
        .await
    }

    // Servers
    async fn list_servers(&self) -> anyhow::Result<Value> {
        let raw = self.api_get("/servers").await?;
        Ok(shape_server_list(&raw))
    }

    async fn get_server(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/servers/{uuid}")).await
    }

    async fn validate_server(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/servers/{uuid}/validate")).await
    }

    async fn get_server_resources(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/servers/{uuid}/resources")).await
    }

    async fn get_server_domains(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/servers/{uuid}/domains")).await
    }

    // Deployments
    async fn list_deployments(&self) -> anyhow::Result<Value> {
        self.api_get("/deployments").await
    }

    async fn get_deployment(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_get(&format!("/deployments/{uuid}")).await
    }

    async fn cancel_deployment(&self, uuid: &str) -> anyhow::Result<Value> {
        self.api_post(&format!("/deployments/{uuid}/cancel"), None)
            .await
    }

    // Environment variables
    async fn list_envs(
        &self,
        resource_type: &str,
        uuid: &str,
    ) -> anyhow::Result<Value> {
        let path = match resource_type {
            "application" => format!("/applications/{uuid}/envs"),
            "service" => format!("/services/{uuid}/envs"),
            "database" => format!("/databases/{uuid}/envs"),
            _ => anyhow::bail!(
                "Invalid resource_type for list_envs: {resource_type}. Use: application, service, database"
            ),
        };
        self.api_get(&path).await
    }

    async fn create_env(
        &self,
        resource_type: &str,
        uuid: &str,
        data: &Value,
    ) -> anyhow::Result<Value> {
        let path = match resource_type {
            "application" => format!("/applications/{uuid}/envs"),
            "service" => format!("/services/{uuid}/envs"),
            "database" => format!("/databases/{uuid}/envs"),
            _ => anyhow::bail!(
                "Invalid resource_type for create_env: {resource_type}. Use: application, service, database"
            ),
        };
        self.api_post(&path, Some(data)).await
    }

    async fn delete_env(
        &self,
        resource_type: &str,
        uuid: &str,
        env_uuid: &str,
    ) -> anyhow::Result<Value> {
        let path = match resource_type {
            "application" => format!("/applications/{uuid}/envs/{env_uuid}"),
            "service" => format!("/services/{uuid}/envs/{env_uuid}"),
            "database" => format!("/databases/{uuid}/envs/{env_uuid}"),
            _ => anyhow::bail!(
                "Invalid resource_type for delete_env: {resource_type}. Use: application, service, database"
            ),
        };
        self.api_delete(&path).await
    }

    // Resources (cross-type)
    async fn list_resources(&self) -> anyhow::Result<Value> {
        self.api_get("/resources").await
    }

    // Version
    async fn get_version(&self) -> anyhow::Result<Value> {
        self.api_get("/version").await
    }

    // ── Environment protection ─────────────────────────────────────────

    /// For resource-level mutations, attempt to discover which environment the
    /// resource belongs to and block if protected.
    ///
    /// This looks up the resource and checks its `environment_name` or
    /// `environment.name` field against the protected list.
    async fn check_resource_environment_protection(
        &self,
        resource_type: &str,
        uuid: &str,
    ) -> anyhow::Result<()> {
        let path = match resource_type {
            "application" => format!("/applications/{uuid}"),
            "service" => format!("/services/{uuid}"),
            "database" => format!("/databases/{uuid}"),
            _ => return Ok(()), // Unknown resource types pass through
        };

        // Fetch the resource to find its environment
        let resource = self.api_get(&path).await?;

        let env_name = resource
            .get("environment")
            .and_then(|e| e.get("name"))
            .and_then(|n| n.as_str())
            .or_else(|| {
                resource
                    .get("environment_name")
                    .and_then(|n| n.as_str())
            });

        if let Some(name) = env_name {
            if self.is_environment_protected(name) {
                anyhow::bail!(
                    "BLOCKED: Resource {uuid} belongs to protected environment '{name}'. \
                     Mutating operations on protected environments are not allowed. \
                     Protected environments: {:?}",
                    self.protected_environments
                );
            }
        }

        Ok(())
    }
}

// ── Action classification ──────────────────────────────────────────────

/// Whether an action is read-only or mutating.
fn action_operation(action: &str) -> ToolOperation {
    match action {
        "list_projects" | "get_project" | "list_environments" | "get_environment"
        | "list_applications" | "get_application" | "get_application_logs"
        | "list_services" | "get_service"
        | "list_databases" | "get_database"
        | "list_backups" | "get_backup" | "list_backup_executions"
        | "list_servers" | "get_server" | "validate_server" | "get_server_resources"
        | "get_server_domains"
        | "list_deployments" | "get_deployment"
        | "list_envs" | "list_resources" | "get_version" => ToolOperation::Read,
        _ => ToolOperation::Act,
    }
}

/// Whether an action mutates a resource that could be environment-protected.
fn action_needs_env_protection_check(action: &str) -> Option<&str> {
    match action {
        "deploy_application" | "stop_application" | "restart_application"
        | "update_application" => Some("application"),
        "start_service" | "stop_service" | "restart_service" => Some("service"),
        "start_database" | "stop_database" | "restart_database" => Some("database"),
        "create_env" | "delete_env" => None, // These check via resource_type param
        "cancel_deployment" => None,         // Deployments aren't env-scoped directly
        _ => None,
    }
}

// ── All valid actions ──────────────────────────────────────────────────

const ALL_ACTIONS: &[&str] = &[
    // Read-only
    "list_projects",
    "get_project",
    "list_environments",
    "get_environment",
    "list_applications",
    "get_application",
    "get_application_logs",
    "list_services",
    "get_service",
    "list_databases",
    "get_database",
    "list_backups",
    "get_backup",
    "list_backup_executions",
    "list_servers",
    "get_server",
    "validate_server",
    "get_server_resources",
    "get_server_domains",
    "list_deployments",
    "get_deployment",
    "list_envs",
    "list_resources",
    "get_version",
    // Mutating
    "deploy_application",
    "stop_application",
    "restart_application",
    "update_application",
    "start_service",
    "stop_service",
    "restart_service",
    "start_database",
    "stop_database",
    "restart_database",
    "cancel_deployment",
    "create_backup",
    "delete_backup",
    "create_env",
    "delete_env",
];

// ── Tool trait implementation ──────────────────────────────────────────

#[async_trait]
impl Tool for CoolifyTool {
    fn name(&self) -> &str {
        "coolify"
    }

    fn description(&self) -> &str {
        "Manage a Coolify cluster: projects, environments, applications, services, \
         databases, servers, and deployments. Supports environment-level protection \
         to prevent accidental mutations on production."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ALL_ACTIONS,
                    "description": "The Coolify API action to perform"
                },
                "uuid": {
                    "type": "string",
                    "description": "Resource UUID (required for get/update/start/stop/restart/deploy/delete actions)"
                },
                "project_uuid": {
                    "type": "string",
                    "description": "Project UUID (required for list_environments, get_environment)"
                },
                "environment": {
                    "type": "string",
                    "description": "Environment name or UUID (required for get_environment)"
                },
                "resource_type": {
                    "type": "string",
                    "enum": ["application", "service", "database"],
                    "description": "Resource type (required for list_envs, create_env, delete_env)"
                },
                "data": {
                    "type": "object",
                    "description": "Request body for update_application, create_env"
                },
                "env_uuid": {
                    "type": "string",
                    "description": "Environment variable UUID (required for delete_env)"
                },
                "db_uuid": {
                    "type": "string",
                    "description": "Database UUID (required for backup actions: list_backups, create_backup, get_backup, delete_backup, list_backup_executions)"
                },
                "backup_uuid": {
                    "type": "string",
                    "description": "Backup UUID (required for get_backup, delete_backup, list_backup_executions)"
                },
                "lines": {
                    "type": "integer",
                    "description": "Number of log lines to retrieve (default 100, max 1000)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        let action = match args.get("action").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some("Missing required parameter: action".into()),
                });
            }
        };

        // Validate action is known
        if !ALL_ACTIONS.contains(&action) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Unknown action: {action}. Valid actions: {ALL_ACTIONS:?}"
                )),
            });
        }

        // Check action allowlist
        if !self.is_action_allowed(action) {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!(
                    "Action '{action}' is not in the allowed_actions list. \
                     Currently allowed: {:?}. \
                     Update coolify.allowed_actions in config to enable it.",
                    self.allowed_actions
                )),
            });
        }

        // Enforce security policy
        let operation = action_operation(action);
        if let Err(error) = self.security.enforce_tool_operation(operation, "coolify") {
            return Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(error),
            });
        }

        // Helper closures for parameter extraction
        let get_str = |key: &str| -> Option<&str> { args.get(key).and_then(|v| v.as_str()) };

        let require_str = |key: &str| -> Result<&str, ToolResult> {
            get_str(key).ok_or_else(|| ToolResult {
                success: false,
                output: String::new(),
                error: Some(format!("{action} requires '{key}' parameter")),
            })
        };

        // Like require_str but also validates the value is safe for URL path
        // interpolation (prevents path traversal via crafted UUIDs).
        let require_path_param = |key: &str| -> Result<&str, ToolResult> {
            let value = require_str(key)?;
            validate_path_segment(value, key).map_err(|e| ToolResult {
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
            })?;
            Ok(value)
        };

        let require_uuid = || -> Result<&str, ToolResult> { require_path_param("uuid") };

        // Environment protection check for direct resource mutations
        if let Some(resource_type) = action_needs_env_protection_check(action) {
            let uuid = match require_uuid() {
                Ok(u) => u,
                Err(e) => return Ok(e),
            };
            if let Err(e) = self
                .check_resource_environment_protection(resource_type, uuid)
                .await
            {
                return Ok(ToolResult {
                    success: false,
                    output: String::new(),
                    error: Some(e.to_string()),
                });
            }
        }

        // For env var mutations, check protection via resource_type + uuid
        if matches!(action, "create_env" | "delete_env") {
            if let (Some(resource_type), Some(uuid)) = (get_str("resource_type"), get_str("uuid")) {
                if validate_path_segment(uuid, "uuid").is_ok() {
                    if let Err(e) = self
                        .check_resource_environment_protection(resource_type, uuid)
                        .await
                    {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }

        // For backup mutations, check protection via db_uuid
        if matches!(action, "create_backup" | "delete_backup") {
            if let Some(db_uuid) = get_str("db_uuid") {
                if validate_path_segment(db_uuid, "db_uuid").is_ok() {
                    if let Err(e) = self
                        .check_resource_environment_protection("database", db_uuid)
                        .await
                    {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }

        // Dispatch to action handler
        let result = match action {
            // Projects
            "list_projects" => self.list_projects().await,
            "get_project" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_project(uuid).await
            }

            // Environments
            "list_environments" => {
                let project_uuid = match require_path_param("project_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.list_environments(project_uuid).await
            }
            "get_environment" => {
                let project_uuid = match require_path_param("project_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let environment = match require_path_param("environment") {
                    Ok(e) => e,
                    Err(e) => return Ok(e),
                };
                self.get_environment(project_uuid, environment).await
            }

            // Applications
            "list_applications" => self.list_applications().await,
            "get_application" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_application(uuid).await
            }
            "deploy_application" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.deploy_application(uuid).await
            }
            "stop_application" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.stop_application(uuid).await
            }
            "restart_application" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.restart_application(uuid).await
            }
            "get_application_logs" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let lines = args.get("lines").and_then(|v| v.as_u64()).map(|n| n as u32);
                self.get_application_logs(uuid, lines).await
            }
            "update_application" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let data = match args.get("data") {
                    Some(d) => d,
                    None => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("update_application requires 'data' parameter".into()),
                        });
                    }
                };
                self.update_application(uuid, data).await
            }

            // Services
            "list_services" => self.list_services().await,
            "get_service" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_service(uuid).await
            }
            "start_service" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.start_service(uuid).await
            }
            "stop_service" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.stop_service(uuid).await
            }
            "restart_service" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.restart_service(uuid).await
            }

            // Databases
            "list_databases" => self.list_databases().await,
            "get_database" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_database(uuid).await
            }
            "start_database" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.start_database(uuid).await
            }
            "stop_database" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.stop_database(uuid).await
            }
            "restart_database" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.restart_database(uuid).await
            }

            // Database backups
            "list_backups" => {
                let db_uuid = match require_path_param("db_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.list_backups(db_uuid).await
            }
            "get_backup" => {
                let db_uuid = match require_path_param("db_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let backup_uuid = match require_path_param("backup_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_backup(db_uuid, backup_uuid).await
            }
            "create_backup" => {
                let db_uuid = match require_path_param("db_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let data = match args.get("data") {
                    Some(d) => d,
                    None => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("create_backup requires 'data' parameter".into()),
                        });
                    }
                };
                self.create_backup(db_uuid, data).await
            }
            "delete_backup" => {
                let db_uuid = match require_path_param("db_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let backup_uuid = match require_path_param("backup_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.delete_backup(db_uuid, backup_uuid).await
            }
            "list_backup_executions" => {
                let db_uuid = match require_path_param("db_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let backup_uuid = match require_path_param("backup_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.list_backup_executions(db_uuid, backup_uuid).await
            }

            // Servers
            "list_servers" => self.list_servers().await,
            "get_server" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_server(uuid).await
            }
            "validate_server" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.validate_server(uuid).await
            }
            "get_server_resources" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_server_resources(uuid).await
            }

            "get_server_domains" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_server_domains(uuid).await
            }

            // Deployments
            "list_deployments" => self.list_deployments().await,
            "get_deployment" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.get_deployment(uuid).await
            }
            "cancel_deployment" => {
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.cancel_deployment(uuid).await
            }

            // Environment variables
            "list_envs" => {
                let resource_type = match require_str("resource_type") {
                    Ok(r) => r,
                    Err(e) => return Ok(e),
                };
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.list_envs(resource_type, uuid).await
            }
            "create_env" => {
                let resource_type = match require_str("resource_type") {
                    Ok(r) => r,
                    Err(e) => return Ok(e),
                };
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let data = match args.get("data") {
                    Some(d) => d,
                    None => {
                        return Ok(ToolResult {
                            success: false,
                            output: String::new(),
                            error: Some("create_env requires 'data' parameter".into()),
                        });
                    }
                };
                self.create_env(resource_type, uuid, data).await
            }
            "delete_env" => {
                let resource_type = match require_str("resource_type") {
                    Ok(r) => r,
                    Err(e) => return Ok(e),
                };
                let uuid = match require_uuid() {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                let env_uuid = match require_path_param("env_uuid") {
                    Ok(u) => u,
                    Err(e) => return Ok(e),
                };
                self.delete_env(resource_type, uuid, env_uuid).await
            }

            // Meta
            "list_resources" => self.list_resources().await,
            "get_version" => self.get_version().await,

            _ => unreachable!(), // Already validated above
        };

        match result {
            Ok(value) => Ok(ToolResult {
                success: true,
                output: serde_json::to_string_pretty(&value)
                    .unwrap_or_else(|_| value.to_string()),
                error: None,
            }),
            Err(e) => Ok(ToolResult {
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
            }),
        }
    }
}

// ── Response shaping ───────────────────────────────────────────────────
// Keep responses concise for the LLM — extract the fields that matter.

fn shape_project_list(raw: &Value) -> Value {
    if let Some(arr) = raw.as_array() {
        let shaped: Vec<Value> = arr
            .iter()
            .map(|p| {
                json!({
                    "uuid": p.get("uuid"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "environments": p.get("environments")
                        .and_then(|e| e.as_array())
                        .map(|envs| envs.iter().map(|e| {
                            json!({
                                "uuid": e.get("uuid"),
                                "name": e.get("name"),
                            })
                        }).collect::<Vec<_>>())
                })
            })
            .collect();
        json!(shaped)
    } else {
        raw.clone()
    }
}

fn shape_application_list(raw: &Value) -> Value {
    if let Some(arr) = raw.as_array() {
        let shaped: Vec<Value> = arr
            .iter()
            .map(|a| shape_application(a))
            .collect();
        json!(shaped)
    } else {
        raw.clone()
    }
}

fn shape_application(raw: &Value) -> Value {
    json!({
        "uuid": raw.get("uuid"),
        "name": raw.get("name"),
        "description": raw.get("description"),
        "fqdn": raw.get("fqdn"),
        "status": raw.get("status"),
        "repository": raw.get("git_repository"),
        "branch": raw.get("git_branch"),
        "build_pack": raw.get("build_pack"),
        "environment": raw.get("environment").map(|e| json!({
            "name": e.get("name"),
            "uuid": e.get("uuid"),
        })),
        "project": raw.get("project").map(|p| json!({
            "name": p.get("name"),
            "uuid": p.get("uuid"),
        })),
    })
}

fn shape_service_list(raw: &Value) -> Value {
    if let Some(arr) = raw.as_array() {
        let shaped: Vec<Value> = arr
            .iter()
            .map(|s| {
                json!({
                    "uuid": s.get("uuid"),
                    "name": s.get("name"),
                    "description": s.get("description"),
                    "type": s.get("type"),
                    "status": s.get("status"),
                    "environment": s.get("environment").map(|e| json!({
                        "name": e.get("name"),
                        "uuid": e.get("uuid"),
                    })),
                })
            })
            .collect();
        json!(shaped)
    } else {
        raw.clone()
    }
}

fn shape_database_list(raw: &Value) -> Value {
    if let Some(arr) = raw.as_array() {
        let shaped: Vec<Value> = arr
            .iter()
            .map(|d| {
                json!({
                    "uuid": d.get("uuid"),
                    "name": d.get("name"),
                    "type": d.get("type"),
                    "status": d.get("status"),
                    "environment": d.get("environment").map(|e| json!({
                        "name": e.get("name"),
                        "uuid": e.get("uuid"),
                    })),
                })
            })
            .collect();
        json!(shaped)
    } else {
        raw.clone()
    }
}

fn shape_server_list(raw: &Value) -> Value {
    if let Some(arr) = raw.as_array() {
        let shaped: Vec<Value> = arr
            .iter()
            .map(|s| {
                json!({
                    "uuid": s.get("uuid"),
                    "name": s.get("name"),
                    "description": s.get("description"),
                    "ip": s.get("ip"),
                    "is_reachable": s.get("is_reachable"),
                    "is_usable": s.get("is_usable"),
                })
            })
            .collect();
        json!(shaped)
    } else {
        raw.clone()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityPolicy;

    fn test_tool() -> CoolifyTool {
        let security = Arc::new(SecurityPolicy::default());
        CoolifyTool::new(
            "https://coolify.test".into(),
            "test-key".into(),
            vec![
                "list_projects".into(),
                "get_project".into(),
                "list_applications".into(),
                "get_application".into(),
                "get_application_logs".into(),
                "list_environments".into(),
                "get_environment".into(),
                "list_services".into(),
                "list_databases".into(),
                "list_backups".into(),
                "list_backup_executions".into(),
                "list_servers".into(),
                "get_server_domains".into(),
                "get_version".into(),
            ],
            vec!["production".into()],
            security,
            30,
        )
    }

    #[test]
    fn tool_name_is_coolify() {
        assert_eq!(test_tool().name(), "coolify");
    }

    #[test]
    fn parameters_schema_requires_action() {
        let schema = test_tool().parameters_schema();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("action")));
    }

    #[test]
    fn all_actions_present_in_schema() {
        let schema = test_tool().parameters_schema();
        let actions = schema["properties"]["action"]["enum"].as_array().unwrap();
        let action_strs: Vec<&str> = actions.iter().filter_map(|v| v.as_str()).collect();
        for a in ALL_ACTIONS {
            assert!(action_strs.contains(a), "Missing action in schema: {a}");
        }
    }

    #[tokio::test]
    async fn execute_missing_action_returns_error() {
        let tool = test_tool();
        let result = tool.execute(json!({})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("action"));
    }

    #[tokio::test]
    async fn execute_unknown_action_returns_error() {
        let tool = test_tool();
        let result = tool.execute(json!({"action": "nuke_everything"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("Unknown action"));
    }

    #[tokio::test]
    async fn disallowed_action_returns_error() {
        let tool = test_tool();
        let result = tool
            .execute(json!({"action": "deploy_application", "uuid": "abc"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("not in the allowed_actions"));
    }

    #[tokio::test]
    async fn get_project_missing_uuid_returns_error() {
        let tool = test_tool();
        let result = tool.execute(json!({"action": "get_project"})).await.unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("uuid"));
    }

    #[tokio::test]
    async fn list_environments_missing_project_uuid_returns_error() {
        let tool = test_tool();
        let result = tool
            .execute(json!({"action": "list_environments"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("project_uuid"));
    }

    #[test]
    fn environment_protection_is_case_insensitive() {
        let tool = test_tool();
        assert!(tool.is_environment_protected("Production"));
        assert!(tool.is_environment_protected("PRODUCTION"));
        assert!(tool.is_environment_protected("production"));
        assert!(!tool.is_environment_protected("staging"));
    }

    #[test]
    fn action_classification_is_correct() {
        assert!(matches!(action_operation("list_projects"), ToolOperation::Read));
        assert!(matches!(action_operation("get_application"), ToolOperation::Read));
        assert!(matches!(action_operation("get_application_logs"), ToolOperation::Read));
        assert!(matches!(action_operation("deploy_application"), ToolOperation::Act));
        assert!(matches!(action_operation("stop_service"), ToolOperation::Act));
        assert!(matches!(action_operation("delete_env"), ToolOperation::Act));
    }

    #[test]
    fn response_shaping_handles_empty_array() {
        let raw = json!([]);
        assert_eq!(shape_project_list(&raw), json!([]));
        assert_eq!(shape_application_list(&raw), json!([]));
        assert_eq!(shape_service_list(&raw), json!([]));
        assert_eq!(shape_database_list(&raw), json!([]));
        assert_eq!(shape_server_list(&raw), json!([]));
    }

    #[test]
    fn response_shaping_extracts_key_fields() {
        let raw = json!([{
            "uuid": "abc-123",
            "name": "my-app",
            "fqdn": "https://app.example.com",
            "status": "running",
            "git_repository": "https://github.com/org/repo",
            "git_branch": "main",
            "build_pack": "nixpacks",
            "some_huge_field": "x".repeat(10000),
        }]);
        let shaped = shape_application_list(&raw);
        let first = &shaped[0];
        assert_eq!(first["uuid"], "abc-123");
        assert_eq!(first["name"], "my-app");
        assert!(first.get("some_huge_field").is_none());
    }

    #[test]
    fn validate_path_segment_blocks_traversal() {
        assert!(validate_path_segment("abc-123-def", "uuid").is_ok());
        assert!(validate_path_segment("simple-uuid", "uuid").is_ok());

        // Path traversal attempts
        assert!(validate_path_segment("../../admin", "uuid").is_err());
        assert!(validate_path_segment("foo/bar", "uuid").is_err());
        assert!(validate_path_segment("foo\\bar", "uuid").is_err());
        assert!(validate_path_segment("..", "uuid").is_err());
        assert!(validate_path_segment("", "uuid").is_err());

        // Control characters
        assert!(validate_path_segment("foo\0bar", "uuid").is_err());
        assert!(validate_path_segment("foo\nbar", "uuid").is_err());
    }

    #[tokio::test]
    async fn path_traversal_uuid_is_rejected() {
        let tool = test_tool();
        let result = tool
            .execute(json!({"action": "get_application", "uuid": "../../admin"}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.error.as_deref().unwrap().contains("forbidden characters"));
    }

    #[test]
    fn action_classification_includes_new_actions() {
        // Backup reads
        assert!(matches!(action_operation("list_backups"), ToolOperation::Read));
        assert!(matches!(action_operation("get_backup"), ToolOperation::Read));
        assert!(matches!(action_operation("list_backup_executions"), ToolOperation::Read));
        // Backup mutations
        assert!(matches!(action_operation("create_backup"), ToolOperation::Act));
        assert!(matches!(action_operation("delete_backup"), ToolOperation::Act));
        // Server domains
        assert!(matches!(action_operation("get_server_domains"), ToolOperation::Read));
    }
}
