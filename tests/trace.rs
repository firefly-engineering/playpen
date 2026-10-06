//! `playpen run --trace-denials` on macOS ([spec §14.5]), end to end: the kernel's denials of
//! this run land in the file, nothing reaches stderr, and the boundary is the one an untraced run
//! gets.
//!
//! [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials

#![cfg(target_os = "macos")]

mod common;

use std::io::Write;

use common::{Fixture, os_bin};

#[test]
fn a_traced_run_writes_its_denials_to_the_file_and_nothing_to_stderr() {
    let fx = Fixture::new();
    let mut decoy = tempfile::NamedTempFile::new().expect("decoy");
    decoy.write_all(b"decoy").expect("write decoy");
    // Logged as the kernel resolved it, through macOS's `/var` link.
    let decoy = decoy.path().canonicalize().expect("decoy path");
    let decoy = decoy.to_str().expect("utf-8 path");
    let trace = fx.state_home().join("trace");
    // `; true` keeps the shell from replacing itself, so the denied read is a descendant's.
    let script = format!("'{}' read '{decoy}'; true", fx.probe().display());

    let launch = |traced: bool| {
        let mut command = fx.playpen(&["run"]);
        if traced {
            command.arg("--trace-denials").arg(&trace);
        }
        command
            .args(["--profile", "p", "--agent", "claude", "--policy"])
            .arg(&fx.policy)
            .args(["--", &os_bin("sh"), "-c", &script]);
        let output = command.output().expect("playpen");
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let id = fx.run_ids().pop().expect("a record");
        // The run scratch is named for the run, so the id is all two runs' grants can differ by.
        let caps = &fx.record(&id)["capabilities"];
        assert!(
            caps.is_object(),
            "a launched run records its grants: {caps}"
        );
        let caps = caps.to_string().replace(&id, "<run>");
        (output.stdout, caps)
    };
    let (plain, untraced) = launch(false);
    let (seen, traced) = launch(true);
    let record = fx.record(&fx.run_ids().pop().expect("a record"));
    assert_eq!(record["denial_trace"], trace.to_str().unwrap());
    assert!(record["denial_trace_unverified"].is_null(), "{record}");

    let written = std::fs::read_to_string(&trace).expect("the trace");
    assert!(
        written.contains(&format!("deny(1) file-read-data {decoy}")),
        "{written}"
    );
    assert!(!written.contains("# playpen: unverified"), "{written}");
    // The boundary is the same with and without the flag: the same capabilities, and the same
    // verdict from the probe.
    assert_eq!(traced, untraced);
    assert_eq!(seen, plain);
}
