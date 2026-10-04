# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

Edit the right-hand column to match whatever vocabulary you actually use.

## OS labels

playpen enforces through a different mechanism per platform (Seatbelt, Landlock) and its floor has per-platform contents, so a great many issues are true on one OS flavour and meaningless on another. These labels record that.

| Label       | Meaning                                                                   |
| ----------- | ------------------------------------------------------------------------- |
| `os:darwin` | Specific to macOS                                                         |
| `os:linux`  | Specific to Linux generally, FHS hosts and NixOS alike                    |
| `os:nixos`  | Specific to NixOS, or to any host whose OS is not an FHS tree             |

These are a **separate axis from triage**, not a sixth role. An OS label is applied _in addition to_ a triage label and never instead of one: `os:nixos` + `needs-info` is an ordinary state.

How to apply them:

- **Use the narrowest set that is true.** An issue reproducible only on a non-FHS host is `os:nixos` alone — do not add `os:linux` as well merely because NixOS is Linux. Add `os:linux` too only when ordinary FHS Linux is affected in its own right.
- **More than one is fine** when more than one applies: an issue affecting macOS and Linux but not NixOS takes `os:darwin` and `os:linux`.
- **Most issues get none.** Absence means "not OS-specific", which is the common case, so labelling everything drains the signal. Leave them off unless the OS is part of the problem.

The useful test is not which OS the reporter happened to be on, but **whether the diagnosis or the fix differs per flavour**. A build that fails on NixOS because the host ships no `cc` is `os:nixos`: the cause is that the OS is a package store rather than an FHS tree, and the fix exists nowhere else. A Landlock ABI question is `os:linux`: it is the same question on every distribution, NixOS included.

`os:nixos` is the one that gets mislabelled, because NixOS is Linux and the instinct is to reach for `os:linux`. Prefer `os:nixos` whenever the issue turns on the OS not being an FHS tree — no `/bin/sh`, no system `cc`, libraries reached by store path, the floor needing a declared closure ([ADR 0023](../adr/0023-the-floor-on-a-non-fhs-host-is-a-declared-closure.md)).
