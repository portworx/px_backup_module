# Portworx Backup Module

This project provides modules that help manage and automate PX-Backup operations.

## Added Modules:

1. [Ansible Collection](ansible-collection/README.md) - Collection of Ansible modules for managing PX-Backup resources including.

For detailed documentation and usage examples, please refer to the specific module READMEs.

## Developer Tooling

- [proto-sync Claude Code skill](.claude/skills/proto-sync/README.md) - Propagates a `px-backup-api` proto/swagger change into the Ansible collection (module, docs, examples, inventory). Run `/proto-sync <base-ref> <head-ref>` from Claude Code in the repo root.