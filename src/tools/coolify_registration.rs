// ── Registration snippet for src/tools/mod.rs ─────────────────────────
//
// Add this block alongside the Notion/Jira registration blocks in
// `all_tools_with_runtime()`. It follows the same config-gating pattern.
//
// Prerequisites:
// 1. Add `pub mod coolify_tool;` to the module declarations in mod.rs
// 2. Add `pub use coolify_tool::CoolifyTool;` to the re-exports
// 3. Add `pub coolify: CoolifyConfig` to the root Config struct in schema.rs
// 4. Add `use crate::config::CoolifyConfig;` (or re-export from config/mod.rs)
//
// Then insert this block after the Jira registration section:

/*
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
*/
