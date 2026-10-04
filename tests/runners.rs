//! CI runs on pinned runner labels, never `-latest` ([spec §17.1]): the suite's row set is a
//! function of the runner's kernel, so a label that moves on its own changes what the suite
//! asserts with no change to playpen.
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use serde_json::Value;

/// Every label a job names, directly or through its `os` matrix.
fn labels(job: &Value) -> Vec<&str> {
    let matrix = job["strategy"]["matrix"]["os"]
        .as_array()
        .into_iter()
        .flatten();
    std::iter::once(&job["runs-on"])
        .chain(matrix)
        .filter_map(Value::as_str)
        .filter(|label| !label.starts_with("${{"))
        .collect()
}

#[test]
fn ci_runs_on_one_pinned_label_per_platform() {
    let workflow: Value =
        serde_saphyr::from_str(include_str!("../.github/workflows/ci.yml")).expect("ci.yml parses");
    let jobs = workflow["jobs"].as_object().expect("ci.yml has jobs");
    let labels: Vec<&str> = jobs.values().flat_map(labels).collect();
    for label in &labels {
        assert!(!label.ends_with("-latest"), "{label} is not pinned");
    }
    assert!(labels.contains(&"ubuntu-24.04"), "{labels:?}");
    assert!(
        labels.iter().any(|label| label.starts_with("macos-")),
        "{labels:?}"
    );
}
