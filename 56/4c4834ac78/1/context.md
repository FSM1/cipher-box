# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Plan: Database Schema Evolution Protocol

## Context

Phase 14 exposed a gap: new TypeORM entities were added without a corresponding `CREATE TABLE` migration, breaking the staging deploy. The IPFS metadata side has a formal evolution protocol (`docs/METADATA_EVOLUTION_PROTOCOL.md`) but there's no equivalent for the PostgreSQL database schema. This doc will formalize the rules, conventions, and checklist for database migrations to prevent the same class of error ...

### Prompt 2

ok can you fix the device_approvals gap identified? Will this require a staging reset to fix?

### Prompt 3

but the fresh install will always run all the available migrations, why would you repeat creating the table in the full schema if it will be created in the dedicated migration?

### Prompt 4

ok push all this up and lets get it merged.

