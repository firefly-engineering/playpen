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
        /// codes mean the broker denied a live agent one request.
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
    WorkspaceWorktreeOnReadRoot => "refusal.workspace.worktree-on-read-root",
    RouteAmbiguous => "refusal.route.ambiguous",
    EndpointUnknown => "refusal.endpoint.unknown",
    EndpointUnsatisfiable => "refusal.endpoint.unsatisfiable",
    EnvReserved => "refusal.env.reserved",
    EnvForbidden => "refusal.env.forbidden",
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
    CwdUngranted => "refusal.cwd.ungranted",
    AreaBusy => "refusal.area.busy",
    StateCollision => "refusal.state.collision",
    StateIo => "refusal.state.io",
    ProcessFork => "refusal.process.fork",
    ProcessWait => "refusal.process.wait",
    // Mechanism
    MechanismUnavailable => "refusal.mechanism.unavailable",
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
                matches!(parts.as_slice(), ["refusal" | "broker", subject, reason]
                    if !subject.is_empty() && !reason.is_empty()),
                "{code} is not <prefix>.<subject>.<reason>"
            );
        }
    }
}
