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

## Integration Steps

1. Copy `coolify_tool.rs` into `src/tools/` in the ZeroClaw repo
2. Add `CoolifyConfig` to `src/config/schema.rs` and `src/config/mod.rs`
3. Add the registration block from `coolify_registration.rs` into `src/tools/mod.rs`
4. Merge the tool description into `tool_descriptions/en.toml`
5. Install the skill to `~/.zeroclaw/workspace/skills/coolify-ops/`

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
