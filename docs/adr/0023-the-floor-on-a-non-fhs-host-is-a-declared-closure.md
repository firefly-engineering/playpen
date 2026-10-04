# The floor on a non-FHS host is a declared closure

*Amends [ADR 0014](0014-the-toolchain-is-a-declared-closure.md).*

ADR 0014 bounds the floor by content: read and execute only, only under paths the OS owns, never
under `$HOME`, never under a package store, never anything writable. On a host whose OS *is* a
package store that description names nothing runnable, and the floor cannot be a list of FHS
directories. Such a host supplies a **dedicated floor** instead: a generated directory holding
the OS's own command binaries and, beside them, the **declared closure** they need, one store
path per line. The floor is one read-and-execute root per line. A dedicated floor is selected by
`PLAYPEN_FLOOR`, else taken from the floor the Nix module installed in the running system
generation. The canary ([§8.6](../spec.md#86-the-floor-self-test)) comes from whatever the floor
is on this host, resolved per call, and stays dynamically linked everywhere.

ADR 0014's bound survives intact. What changes is that "paths the OS owns" is answered by the
host rather than by a literal list, and that on one kind of host the answer is a set of store
paths.

## Why

**The floor's own path list is not merely incomplete on NixOS — it is empty of libraries.** Of
the sixteen Linux entries, five exist on the reference NixOS host (`/bin`, `/usr/bin`, `/lib64`,
`/proc`, `/dev`), and `floor()` filters the rest out by its own rule that the floor grants what
exists and nothing in place of what does not. The three that are not kernel interfaces hold
almost nothing: `/bin` holds one entry, a `sh` symlink into the store; `/usr/bin` holds one,
`env`; `/lib64` holds the loader stub alone. Every library, and the ELF interpreter itself, is
named by absolute store path in the binary — `ldd` on the host's `true` resolves seven objects,
all seven under `/nix/store`. So **no list of FHS directories can let a dynamically linked binary
`exec` on this host**, and the failure is not a missing canary but a floor that cannot admit one.
This is the same fact ADR 0014 established when it rejected relocating a closure into one
subtree: Nix binaries carry absolute store paths baked in. There it ruled out an FHS-style view
of the *toolchain*; here it rules out an FHS-style *floor*.

**The consequence is not a test failure but a host playpen cannot run on.** The self-test runs
before every launch and its verdict is never cached, so on a non-FHS host every launch refuses
before forking the agent. The suite reporting eight failing rows was reporting that correctly.
A fix that made the suite green without making the floor work would be the vacuous pass
[ADR 0016](0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md)
calls a defect.

**A declared closure is the shape already established for exactly this problem, and it is
small.** ADR 0014 found that a closure *is* a root list, that no human can write hashed store
paths correctly, and that the mechanical expander is the only author that can. The floor inherits
all three. Measured on the reference host, the closure of `coreutils` and `bash` — the OS command
binaries an FHS floor grants wholesale through `/bin` and `/usr/bin` — is **10 store paths**,
against the 108 ADR 0014 measured for a full agent toolchain and the 1000-to-1100 ceiling it
probed. Verified: under a floor of those 10 roots the dynamically linked canary exits 0 as a
throwaway child, and the suite's ten runnable rows pass.

**Granting the store coarsely is the leak ADR 0014 was written to close, and the dedicated floor
does not do it.** The 120 `home-manager-files` derivations each carrying a readable `.ssh/config`
are still there. A dedicated floor grants one root per declared path, so the store as a whole is
never granted and neither the live nor any stale generation is reachable — the same reason a
toolchain closure is safe where `/nix/store` is not.

**The system generation is the right default, and the right size for it is computed once by its
generator.** `/run/current-system` is OS-owned, root-owned, read-only, and excludes every
per-user profile, so it is what "the OS" means on this host and it contains none of the dotfile
generations. Its closure, however, is **3277 paths and a 0.7-second `nix-store` query** on the
reference host. Because the self-test's verdict is never cached, computing that at launch would
charge every launch for it, and the module that builds the system can write the list for free
instead. So the default is a floor the module *installs inside* the system generation, which
rolls back with the system that built it, and playpen only ever reads the list — keeping the
standing law that playpen has **no runtime Nix dependency**. The same reasoning as ADR 0014's
"the generator already produces a generation and can root the closure there for free", and the
same refusal to call Nix at runtime.

**A dedicated floor carries the OS's commands, not just the canary, because that is what the FHS
floor grants.** `/bin` and `/usr/bin` are floor subtrees, so on an FHS host every OS command, the
shell included, is already inside the floor. A dedicated floor holding only `true` would be a
*narrower* floor masquerading as the same object, and the suite — which runs a shell and `cat`
confined by the floor alone — would then be testing a different floor on each platform, against
ADR 0014's rule that the floor is one object whose spelling never appears in a test.

**`PLAYPEN_FLOOR` describes the host and so is not the policy knob ADR 0014 forbids.** The floor
must be neither widenable nor narrowable by policy, and an environment variable that redefined it
would be exactly that. This one cannot: it selects *which* generated floor is read, and every
grant still comes from that floor's own `closureInfo` list, so nothing hand-written can add a
path. No policy document can name or reach it — a policy has no field for it and no field that
expands to it. It answers "where does this host keep its OS", which on an FHS host is answered by
a compiled-in list and needs no variable at all. The weaker claim worth stating plainly: an
operator who can set the variable can point playpen at a floor of their choosing, but an operator
who can set it can also replace the binary, so it moves no boundary that was not already theirs.

**A static canary was rejected.** It would need no closure and no store grant, making this whole
question disappear. It also exits 0 without ever invoking the loader, and the loader is the half
of `exec` the self-test exists to prove — ADR 0014 records that omitting the floor's root entry
makes every dynamically linked binary abort with `SIGABRT` and zero diagnostic output, which is
precisely what a static canary would fail to notice. The canary stays dynamically linked on every
host.

## Consequences

- **A new code, `refusal.floor.unavailable`.** A host with neither a dedicated floor nor an FHS
  canary has no floor to test, and a dedicated floor whose closure list is missing or empty
  cannot let anything `exec`. Both are said as themselves, naming the remedy, rather than
  surfacing as a canary that could not be confined — the floor is the thing to fix, and nothing
  about the run is.

- **The canary is resolved per call, not once.** It was a `const`; which binary the floor can run
  is a property of the host as it is now, for the same reason the self-test's verdict is never
  cached. The suite's `P-canary` row and the launch path still share one implementation.

- **The suite names binaries, never paths.** A test that wanted `/bin/sh` or `/usr/bin/true`
  asked for a path that does not exist on every supported host. It now asks the floor for a
  binary by name, so a non-FHS host needs no special case and no row is skipped on it.

- **`dash` is a host tool, not a confined target.** The job-control row runs it outside the
  boundary as part of the harness, like the C toolchain, so it is found on `PATH` and supplied by
  the dev shell rather than named at `/bin/dash`.

- **The floor on an FHS host is unchanged.** No dedicated floor is found, the compiled-in list
  applies, and the canary is `/usr/bin/true` or `/bin/true` as before. CI, which runs on
  `ubuntu-24.04` and `macos-15` without the dev shell, takes exactly the old path.

- **The dev shell sets `PLAYPEN_FLOOR` on Linux.** The shell may be entered on a non-FHS host,
  and a suite that cannot find a canary fails for a reason that is about the host rather than
  about the change under test. On an FHS host it is harmless: the same floor, with a 10-path
  closure added.

- **Linux now has a Nix-linked C toolchain in the dev shell.** ADR 0014's reasoning for
  withholding one is a dyld fact: a Nix-linked binary loads from `/nix/store`, which no boundary
  grants, and dies before it can run. That holds on Darwin, where the OS supplies `cc`. On a
  non-FHS Linux host there is no OS `cc` to withhold it in favour of, and the binaries the suite
  confines are reached through the dedicated floor's closure like any other. The shell is
  `mkShellNoCC` on Darwin and `mkShell` on Linux.
