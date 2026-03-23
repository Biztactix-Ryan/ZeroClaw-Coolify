use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Coolify cluster management configuration (`[coolify]`).
///
/// When `enabled = true`, registers the `coolify` tool for managing
/// applications, services, databases, servers, and deployments via
/// the Coolify REST API.
///
/// ## Safety
///
/// - **`allowed_actions`**: Only listed actions can be invoked.
///   Defaults to read-only actions. Add mutating actions explicitly
///   when you're ready to grant them.
///
/// - **`protected_environments`**: Environment names (case-insensitive)
///   where all mutating operations are blocked. Resources belonging to
///   a protected environment cannot be deployed, stopped, restarted,
///   updated, or have their env vars modified.
///   Defaults to `["production"]`.
///
/// ## Auth
///
/// Bearer token auth. Set `api_key` here or via `COOLIFY_API_KEY` env var.
/// Token permissions in Coolify control what the API key can access
/// (`read-only`, `read:sensitive`, `*`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CoolifyConfig {
    /// Enable the `coolify` tool. Default: `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Coolify instance base URL, e.g. `https://coolify.example.com`.
    /// Do NOT include `/api/v1` — the tool appends that.
    #[serde(default)]
    pub base_url: String,

    /// Coolify API token. Falls back to `COOLIFY_API_KEY` env var.
    #[serde(default)]
    pub api_key: String,

    /// Actions the agent is permitted to call.
    /// Defaults to read-only actions only.
    ///
    /// Read-only actions:
    ///   `list_projects`, `get_project`, `list_environments`, `get_environment`,
    ///   `list_applications`, `get_application`, `get_application_logs`,
    ///   `list_services`, `get_service`, `list_databases`, `get_database`,
    ///   `list_backups`, `get_backup`, `list_backup_executions`,
    ///   `list_servers`, `get_server`, `validate_server`, `get_server_resources`,
    ///   `get_server_domains`, `list_deployments`, `get_deployment`,
    ///   `list_envs`, `list_resources`, `get_version`
    ///
    /// Mutating actions (opt-in):
    ///   `deploy_application`, `stop_application`, `restart_application`,
    ///   `update_application`, `start_service`, `stop_service`, `restart_service`,
    ///   `start_database`, `stop_database`, `restart_database`,
    ///   `create_backup`, `delete_backup`,
    ///   `cancel_deployment`, `create_env`, `delete_env`
    #[serde(default = "default_coolify_allowed_actions")]
    pub allowed_actions: Vec<String>,

    /// Environment names where mutating operations are blocked.
    /// Case-insensitive. Default: `["production"]`.
    ///
    /// When a resource (application, service, database) belongs to a
    /// protected environment, deploy/stop/restart/update/env-var mutations
    /// will be rejected with a clear error message.
    #[serde(default = "default_coolify_protected_environments")]
    pub protected_environments: Vec<String>,

    /// Request timeout in seconds. Default: `30`.
    #[serde(default = "default_coolify_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_coolify_allowed_actions() -> Vec<String> {
    vec![
        "list_projects".into(),
        "get_project".into(),
        "list_environments".into(),
        "get_environment".into(),
        "list_applications".into(),
        "get_application".into(),
        "get_application_logs".into(),
        "list_services".into(),
        "get_service".into(),
        "list_databases".into(),
        "get_database".into(),
        "list_backups".into(),
        "get_backup".into(),
        "list_backup_executions".into(),
        "list_servers".into(),
        "get_server".into(),
        "validate_server".into(),
        "get_server_resources".into(),
        "get_server_domains".into(),
        "list_deployments".into(),
        "get_deployment".into(),
        "list_envs".into(),
        "list_resources".into(),
        "get_version".into(),
    ]
}

fn default_coolify_protected_environments() -> Vec<String> {
    vec!["production".into()]
}

fn default_coolify_timeout_secs() -> u64 {
    30
}

impl Default for CoolifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            api_key: String::new(),
            allowed_actions: default_coolify_allowed_actions(),
            protected_environments: default_coolify_protected_environments(),
            timeout_secs: default_coolify_timeout_secs(),
        }
    }
}
