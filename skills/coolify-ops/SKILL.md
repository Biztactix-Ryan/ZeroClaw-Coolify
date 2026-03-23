---
name: coolify-ops
description: Operational knowledge for managing a Coolify cluster — deployment workflows, incident response, and safety practices
version: "0.1.0"
author: biztactix
tags: ["devops", "deployment", "infrastructure", "coolify"]
---

# Coolify Operations

You manage a Coolify cluster using the `coolify` tool. This skill provides operational context for common workflows.

## Key Concepts

- **Projects** contain **Environments** (e.g. production, staging, development)
- **Environments** contain **Resources**: applications, services, databases
- Every resource has a **UUID** — always use UUIDs, never names, for API calls
- **Protected environments** (typically "production") block all mutating operations

## Safety Rules

1. **NEVER** attempt to deploy, stop, restart, or modify resources in production without explicit user confirmation
2. **Always** run `list_projects` and `list_environments` first to understand the topology
3. **Always** check logs before restarting a failing application
4. **Always** verify which environment a resource belongs to before any mutation
5. If the tool blocks an action due to environment protection, **do not** try to work around it — inform the user

## Common Workflows

### Explore the cluster
1. `get_version` — verify API connectivity
2. `list_projects` — see all projects and their environments
3. `list_environments(project_uuid)` — drill into a project
4. `get_environment(project_uuid, environment)` — see all resources in an env

### Check application status
1. `list_applications` — find the app UUID and current status
2. `get_application(uuid)` — get details (repo, branch, build pack, FQDN)
3. `get_application_logs(uuid)` — check recent logs

### Deploy an application (non-production)
1. `get_application(uuid)` — confirm environment and current state
2. Verify the environment is NOT protected
3. `deploy_application(uuid)` — trigger deployment
4. `list_deployments` then `get_deployment(uuid)` — monitor progress

### Investigate a failing service
1. `get_service(uuid)` — check status
2. `list_envs("service", uuid)` — verify configuration
3. `get_server(server_uuid)` — check server health
4. `validate_server(server_uuid)` — verify connectivity

### Server health check
1. `list_servers` — see all servers and reachability
2. `validate_server(uuid)` — test connectivity
3. `get_server_resources(uuid)` — see what's running on it
4. `get_server_domains(uuid)` — see all domains pointing to this server

### Database backup management
1. `list_databases` — find the database UUID
2. `list_backups(db_uuid)` — see existing backup schedules
3. `list_backup_executions(db_uuid, backup_uuid)` — check backup history and last run status
4. `create_backup(db_uuid, data)` — create a new backup schedule
   - data format varies by DB engine; typically includes `frequency`, `save_s3`, `database_name`
5. To verify backups are healthy, check `list_backup_executions` for recent successful runs

### Manage environment variables
1. `list_envs(resource_type, uuid)` — see current vars
2. `create_env(resource_type, uuid, data)` — add a new var
   - data format: `{"key": "NAME", "value": "value", "is_build_time": false}`
3. After changing env vars, the application typically needs a redeploy

## Troubleshooting

- **403 Forbidden**: API may be disabled, or IP not whitelisted in Coolify settings
- **401 Unauthorized**: API key invalid or expired — check `coolify.api_key` config
- **"not in allowed_actions"**: The action needs to be added to `coolify.allowed_actions` in config
- **"protected environment"**: The resource is in production (or another protected env) — mutations are intentionally blocked
