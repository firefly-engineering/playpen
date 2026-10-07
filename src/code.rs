//! The closed, versioned code registry ([spec Appendix A]).
//!
//! Consumers branch on these strings, never on the prose around them, so the set is closed:
//! adding a code is a spec amendment, and every backend error is translated into one of them.
//!
//! [spec Appendix A]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#appendix-a--code-registry

use std::fmt;

macro_rules! registry {
    ($($variant:ident => $code:literal,)*) => {
        /// One stable code. The `refusal.*` codes mean playpen declined to launch; the `broker.*`
        /// codes mean the broker denied a live agent one request; the `bug.*` codes mean playpen
        /// reached a state it has no contract for, and are defects rather than outcomes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Code {
            $($variant,)*
        }

        impl Code {
            /// Every code in the registry, in registry order.
            pub const ALL: &[Code] = &[$(Code::$variant,)*];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(Code::$variant => $code,)*
                }
            }
        }
    };
}

registry! {
    // Policy
    PolicyNotFound => "refusal.policy.not-found",
    PolicyUnreadable => "refusal.policy.unreadable",
    PolicyAmbiguousLocation => "refusal.policy.ambiguous-location",
    PolicySyntax => "refusal.policy.syntax",
    PolicyUnknownField => "refusal.policy.unknown-field",
    PolicyVersion => "refusal.policy.version",
    PolicyTag => "refusal.policy.tag",
    PolicyType => "refusal.policy.type",
    // Coherence
    WorkspaceUnknown => "refusal.workspace.unknown",
    FragmentUnknown => "refusal.fragment.unknown",
    MinterUnknown => "refusal.minter.unknown",
    AreaUnknown => "refusal.area.unknown",
    RouteAmbiguous => "refusal.route.ambiguous",
    EndpointUnknown => "refusal.endpoint.unknown",
    EndpointUnsatisfiable => "refusal.endpoint.unsatisfiable",
    EnvReserved => "refusal.env.reserved",
    EnvForbidden => "refusal.env.forbidden",
    EnvDuplicate => "refusal.env.duplicate",
    RootRelative => "refusal.root.relative",
    // Invocation and selection
    InvocationUsage => "refusal.invocation.usage",
    ShimUnknown => "refusal.shim.unknown",
    KindUnknown => "refusal.kind.unknown",
    SelectionUnknownProfile => "refusal.selection.unknown-profile",
    SelectionNoMatch => "refusal.selection.no-match",
    SelectionAmbiguous => "refusal.selection.ambiguous",
    RunUnknown => "refusal.run.unknown",
    // Host state
    RootMissing => "refusal.root.missing",
    ExclusionMissing => "refusal.exclusion.missing",
    IntegrityWritable => "refusal.integrity.writable",
    IntegrityUnresolvable => "refusal.integrity.unresolvable",
    StateReachable => "refusal.state.reachable",
    CwdUngranted => "refusal.cwd.ungranted",
    AreaBusy => "refusal.area.busy",
    StateCollision => "refusal.state.collision",
    StateIo => "refusal.state.io",
    ProcessFork => "refusal.process.fork",
    ProcessWait => "refusal.process.wait",
    // Mechanism
    MechanismUnavailable => "refusal.mechanism.unavailable",
    FloorUnavailable => "refusal.floor.unavailable",
    FloorSelfTest => "refusal.floor.self-test",
    BudgetExceeded => "refusal.budget.exceeded",
    TargetExec => "refusal.target.exec",
    // Credentials and proxy
    MinterFailed => "refusal.minter.failed",
    MinterMalformed => "refusal.minter.malformed",
    MinterTimeout => "refusal.minter.timeout",
    ProxyBind => "refusal.proxy.bind",
    ProxyCa => "refusal.proxy.ca",
    // Denial trace
    TraceKernelAbi => "refusal.trace.kernel-abi",
    TraceLandlockInactive => "refusal.trace.landlock-inactive",
    TraceBackendNoLogging => "refusal.trace.backend-no-logging",
    TraceNoJournalAccess => "refusal.trace.no-journal-access",
    TraceChannelSilent => "refusal.trace.channel-silent",
    TraceChannelLossy => "refusal.trace.channel-lossy",
    // Broker
    BrokerEndpointDenied => "broker.endpoint.denied",
    // Faults. Not outcomes a caller can provoke or should handle: each one says playpen is
    // broken, and the run ends by `SIGABRT` rather than with a status ([ADR 0024]). A separate
    // prefix, so `R-code-coverage` — which must fail on any `refusal.*` code no suite row
    // produces — never asks for a row that nothing can provoke.
    //
    // [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    BugStatusNoChild => "bug.status.no-child",
    BugStatusUnreadable => "bug.status.unreadable",
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn codes_are_unique() {
        let strings: HashSet<_> = Code::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(strings.len(), Code::ALL.len());
    }

    #[test]
    fn codes_are_prefix_subject_reason() {
        for code in Code::ALL {
            let parts: Vec<_> = code.as_str().split('.').collect();
            assert!(
                matches!(parts.as_slice(), ["refusal" | "broker" | "bug", subject, reason]
                    if !subject.is_empty() && !reason.is_empty()),
                "{code} is not <prefix>.<subject>.<reason>"
            );
        }
    }

    /// The release gate enumerates `refusal.*` and must fail on any such code no row produces, so
    /// a fault's code has to sit outside that prefix ([ADR 0024]).
    ///
    /// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    #[test]
    fn a_fault_is_never_a_refusal() {
        for code in [Code::BugStatusNoChild, Code::BugStatusUnreadable] {
            assert!(
                code.as_str().starts_with("bug."),
                "{code} is not in the fault prefix"
            );
        }
    }
}
