# Lattice Project Instructions & Guidelines

## 1. Universal Language Requirement (Strict Rule)
- **All content within this repository MUST be written in English.**
  - **Source Code**: identifiers, function names, variables, constants, type definitions, logs, CLI outputs, and IPC messages.
  - **Comments**: all code comments (inline, block, docstrings) across all languages (`Rust`, `JavaScript`, `HTML`, `CSS`, `Shell`, etc.).
  - **Documentation**: READMEs, architectural docs, specifications, guides, and plans (`.md`, `.txt`).
  - **User Interfaces**: all UI labels, headings, modal dialogs, buttons, tooltips, alert prompts, and status indicators in both control and node web consoles.
  - **Commit Messages & PRs**: all Git commits, branch names, and pull requests.
- No other languages (including Vietnamese or others) are permitted anywhere in repository files.

## 2. Architecture & Design Principles
- **Separation of Concerns**: Keep control plane (`lattice-control`) and client node (`lattice-node`) strictly decoupled.
- **Port Convention**:
  - `7443`: Control Plane Server Web Console.
  - `7444`: Node Client Web Console.
- **Visual Design**: Professional retro monochrome console aesthetics (black, dark gray, white with targeted amber/green phosphor indicators).
- **Workload Persistence**: Active job leases must persist across daemon/system restarts until explicitly cancelled by the control server.
