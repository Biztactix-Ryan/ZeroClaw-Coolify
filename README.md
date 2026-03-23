# ZeroClaw Coolify Tool

A Coolify API wrapper tool for [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) — the autonomous AI assistant infrastructure.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Skill Layer (coolify-ops/SKILL.md)                 │
│  Operational knowledge: workflows, safety rules,    │
│  troubleshooting guides                             │
├─────────────────────────────────────────────────────┤
│  Tool Layer (coolify_tool.rs)                       │
│  Rust API wrapper: auth, HTTP, error handling,      │
│  response shaping, environment protection           │
├─────────────────────────────────────────────────────┤
│  Config Layer (coolify_config.rs)                   │
│  allowed_actions, protected_environments,           │
│  credentials, timeouts                              │
└─────────────────────────────────────────────────────┘
```

## Safety Features

- **Protected environments**: Environments listed in `protected_environments` (default: `["production"]`) block all mutating operations. The tool fetches the resource to determine its environment before allowing any mutation.

- **Action allowlisting**: Only actions in `allowed_actions` can be called. Defaults to read-only. Mutating actions must be explicitly opted in.

- **Security policy enforcement**: Read actions require `ToolOperation::Read`, mutations require `ToolOperation::Act`.

## Configuration

```toml
[coolify]
enabled = true
base_url = "https://coolify.example.com"
api_key = ""  # or set COOLIFY_API_KEY env var

# Default: all read-only actions. Add mutating actions as needed:
# allowed_actions = ["list_projects", "get_project", ..., "deploy_application", "restart_application"]

# Environments where mutations are blocked (case-insensitive)
protected_environments = ["production"]

timeout_secs = 30
```

## Files

| File | Purpose |
|------|---------|
| `src/tools/coolify_tool.rs` | Tool implementation (Tool trait) |
| `src/config/coolify_config.rs` | Configuration struct (CoolifyConfig) |
| `src/tools/coolify_registration.rs` | Registration snippet for mod.rs |
| `tool_descriptions/coolify.toml` | LLM tool description |
| `skills/coolify-ops/SKILL.md` | Operational skill for the agent |

## Integration into ZeroClaw

### Prerequisites

- A working ZeroClaw build environment (Rust toolchain, the [zeroclaw](https://github.com/zeroclaw-labs/zeroclaw) repo cloned)
- A Coolify instance with an API token (create one in Coolify UI under **Keys & Tokens > API tokens**)

### Step 1: Add the tool source

Copy `src/tools/coolify_tool.rs` into the ZeroClaw source tree:

```bash
cp src/tools/coolify_tool.rs /path/to/zeroclaw/src/tools/coolify_tool.rs
```

Then register the module in `src/tools/mod.rs`:

```rust
// Add to the module declarations (near the top, alongside other tools)
pub mod coolify_tool;

// Add to the re-exports
pub use coolify_tool::CoolifyTool;
```

### Step 2: Add the config struct

Copy `src/config/coolify_config.rs` into ZeroClaw's config directory:

```bash
cp src/config/coolify_config.rs /path/to/zeroclaw/src/config/coolify_config.rs
```

Register it in `src/config/mod.rs`:

```rust
pub mod coolify_config;
pub use coolify_config::CoolifyConfig;
```

Add the field to the root `Config` struct in `src/config/schema.rs`:

```rust
pub struct Config {
    // ... existing fields ...

    /// Coolify cluster management configuration.
    #[serde(default)]
    pub coolify: CoolifyConfig,
}
```

### Step 3: Register the tool

In `src/tools/mod.rs`, inside `all_tools_with_runtime()`, add the registration block (see `src/tools/coolify_registration.rs` for the full snippet):

```rust
// Coolify cluster management (config-gated)
if root_config.coolify.enabled {
    let api_key = if root_config.coolify.api_key.trim().is_empty() {
        std::env::var("COOLIFY_API_KEY").unwrap_or_default()
    } else {
        root_config.coolify.api_key.trim().to_string()
    };
    if api_key.trim().is_empty() {
        tracing::warn!(
            "Coolify tool enabled but no API key found (set coolify.api_key or COOLIFY_API_KEY env var)"
        );
    } else if root_config.coolify.base_url.trim().is_empty() {
        tracing::warn!(
            "Coolify tool enabled but coolify.base_url is empty — skipping registration"
        );
    } else {
        tool_arcs.push(Arc::new(CoolifyTool::new(
            root_config.coolify.base_url.trim().to_string(),
            api_key,
            root_config.coolify.allowed_actions.clone(),
            root_config.coolify.protected_environments.clone(),
            security.clone(),
            root_config.coolify.timeout_secs,
        )));
    }
}
```

### Step 4: Add the tool description

Merge the contents of `tool_descriptions/coolify.toml` into `tool_descriptions/en.toml` in the ZeroClaw repo. This provides the LLM with a description of all available actions.

### Step 5: Install the skill

Copy the skill directory to ZeroClaw's workspace:

```bash
cp -r skills/coolify-ops ~/.zeroclaw/workspace/skills/coolify-ops
```

The skill provides the agent with operational knowledge — common workflows, safety rules, and troubleshooting guides. It does not define any tools itself; it relies on the Rust tool for all API interactions.

### Step 6: Configure

Add to your ZeroClaw `config.toml`:

```toml
[coolify]
enabled = true
base_url = "https://coolify.example.com"
# api_key = "your-token-here"  # or set COOLIFY_API_KEY env var

# Optional: enable mutating actions (read-only by default)
# allowed_actions = [
#   "list_projects", "get_project", "list_environments", "get_environment",
#   "list_applications", "get_application", "get_application_logs",
#   "list_services", "get_service",
#   "list_databases", "get_database",
#   "list_backups", "get_backup", "list_backup_executions",
#   "list_servers", "get_server", "validate_server", "get_server_resources", "get_server_domains",
#   "list_deployments", "get_deployment",
#   "list_envs", "list_resources", "get_version",
#   # Uncomment to enable mutations:
#   # "deploy_application", "stop_application", "restart_application", "update_application",
#   # "start_service", "stop_service", "restart_service",
#   # "start_database", "stop_database", "restart_database",
#   # "create_backup", "delete_backup",
#   # "cancel_deployment",
#   # "create_env", "delete_env",
# ]

# Environments where ALL mutations are blocked (case-insensitive)
protected_environments = ["production"]

timeout_secs = 30
```

### Step 7: Build and verify

```bash
cargo build
# Start ZeroClaw and test with:
# "What version of Coolify is running?"
# "List all projects and their environments"
```

### Coolify API Token Permissions

The Coolify API token controls what the tool can access server-side:

| Token Permission | What it allows |
|-----------------|----------------|
| `read-only` (default) | List and get resources, logs, status — no sensitive data |
| `read:sensitive` | Same as read-only but includes passwords, API keys, connection strings |
| `*` (full access) | All operations including deploy, stop, restart, env var changes |

For most setups, use a `read-only` token initially and upgrade to `*` only when you enable mutating actions in `allowed_actions`. The tool's `protected_environments` provides an additional safety layer on top of the token permissions.

## API Coverage

| Resource | List | Get | Start/Deploy | Stop | Restart | Update | Logs | Env Vars | Other |
|----------|------|-----|--------------|------|---------|--------|------|----------|-------|
| Projects | Y | Y | - | - | - | - | - | - | - |
| Environments | Y | Y | - | - | - | - | - | - | - |
| Applications | Y | Y | Y | Y | Y | Y | Y | Y | - |
| Services | Y | Y | Y | Y | Y | - | - | Y | - |
| Databases | Y | Y | Y | Y | Y | - | - | Y | Backups |
| Servers | Y | Y | - | - | - | - | - | - | Domains, Validate, Resources |
| Deployments | Y | Y | - | - | - | - | - | - | Cancel |
