//! The endpoint `path` glob ([spec §7.6]): two tokens, hand-written, and total.
//!
//! `*` matches exactly one path segment; `**` matches zero or more. **playpen parses the glob
//! itself**, and anything richer — alternation, character classes, anchors, escapes — is a parse
//! refusal naming file, line and column, never a pattern quietly taken literally. There is no
//! regex here on purpose: a regex engine would accept every one of those forms and give each a
//! meaning the spec does not have.
//!
//! The matcher is **total**: every pattern this module accepts matches every string in finite
//! time, with no panic and no borrow of the caller's. The two-pointer walk below is why — one
//! `**` is remembered and retried a segment further along, so backtracking is bounded by the
//! path's own length.
//!
//! **The query string is never matched.** A caller matches the path alone.
//!
//! [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The characters that make a pattern richer than the two tokens, and so a parse refusal. `*` is
/// absent: it is the one metacharacter there is, and [`Glob::parse`] checks where it may stand.
const RICHER: [char; 10] = ['?', '[', ']', '{', '}', '(', ')', '|', '^', '$'];

/// [`RICHER`] as the schema states it, for editors that validate against it: host-absolute, and
/// holding none of those characters.
pub const PATTERN: &str = r"^/[^?\[\]{}()|^$\\]*$";

/// One segment of a parsed pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Matched byte for byte against one segment.
    Literal(String),
    /// `*`: exactly one segment, whatever it holds.
    One,
    /// `**`: zero or more segments.
    Any,
}

/// A parsed endpoint path glob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct Glob {
    /// The pattern as it was written, which is what the manifest and `explain` state.
    pattern: String,
    #[serde(skip)]
    #[schemars(skip)]
    segments: Vec<Segment>,
}

impl Glob {
    /// Parse `pattern`, or say what makes it richer than the two tokens.
    ///
    /// The message is the second half of a sentence beginning "… is not a path glob:", so it
    /// reads as one wherever the parser puts it.
    pub fn parse(pattern: &str) -> Result<Self, String> {
        if !pattern.starts_with('/') {
            return Err("a path is host-absolute, so it begins with `/`".into());
        }
        if let Some(c) = pattern.chars().find(|c| RICHER.contains(c) || *c == '\\') {
            return Err(format!(
                "{c:?} is not one of the two tokens a path glob has; `*` matches exactly one \
                 segment and `**` matches zero or more, and nothing else is a pattern"
            ));
        }
        let mut segments = Vec::new();
        for segment in pattern[1..].split('/') {
            segments.push(match segment {
                "*" => Segment::One,
                "**" => Segment::Any,
                literal if literal.contains('*') => {
                    return Err(format!(
                        "the segment {literal:?} mixes `*` with other characters; `*` and `**` \
                         are whole segments, never parts of one"
                    ));
                }
                literal => Segment::Literal(literal.to_owned()),
            });
        }
        Ok(Self {
            pattern: pattern.to_owned(),
            segments,
        })
    }

    /// The pattern as it was written.
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Whether `path` matches. `path` is host-absolute and carries no query string; anything else
    /// matches nothing.
    pub fn matches(&self, path: &str) -> bool {
        let Some(path) = path.strip_prefix('/') else {
            return false;
        };
        let parts: Vec<&str> = path.split('/').collect();
        // Two pointers, and the last `**` remembered: on a mismatch the walk returns to it and
        // lets it swallow one more segment. One `**` needs one bookmark, so this terminates after
        // at most one retry per segment.
        let (mut pattern, mut part) = (0, 0);
        let mut bookmark: Option<(usize, usize)> = None;
        while part < parts.len() {
            match self.segments.get(pattern) {
                Some(Segment::Any) => {
                    bookmark = Some((pattern, part));
                    pattern += 1;
                }
                Some(Segment::One) => {
                    pattern += 1;
                    part += 1;
                }
                Some(Segment::Literal(literal)) if literal == parts[part] => {
                    pattern += 1;
                    part += 1;
                }
                _ => match bookmark {
                    Some((at, swallowed)) => {
                        pattern = at + 1;
                        part = swallowed + 1;
                        bookmark = Some((at, swallowed + 1));
                    }
                    None => return false,
                },
            }
        }
        // Whatever is left of the pattern must be able to match nothing at all.
        self.segments[pattern.min(self.segments.len())..]
            .iter()
            .all(|segment| *segment == Segment::Any)
    }

    /// Whether **some** host-absolute path beginning with `prefix` matches this pattern — what
    /// `refusal.endpoint.unsatisfiable` is decided from ([spec §7.6]). A rule that can match no
    /// path the route it sits on would ever select is a rule the operator wrote for a different
    /// route, and silently allowing nothing is worse than saying so.
    ///
    /// `prefix` is a route's `path_prefix`, which is a **literal string** and not a segment list:
    /// it may stop in the middle of a segment (`/repos/op`) or on a separator (`/repos/op/`).
    /// So it decomposes into whole segments the path must equal, then one partial segment the
    /// path's own may extend, after which the path is free.
    ///
    /// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
    pub fn satisfiable_under(&self, prefix: &str) -> bool {
        let prefix = prefix.strip_prefix('/').unwrap_or(prefix);
        // `split` always yields at least one part, so the pop leaves the whole segments behind.
        let mut fixed: Vec<&str> = prefix.split('/').collect();
        let partial = fixed.pop().unwrap_or_default();
        reachable(&self.segments, &fixed, partial)
    }
}

/// Whether `segments` matches some path that begins with the whole segments `fixed`, then one
/// segment beginning with `partial`, then any number of segments chosen freely.
///
/// Recursive rather than two-pointer, because it decides *existence* and so must try both of
/// `**`'s readings rather than one with a bookmark. Exponential in the pattern's length, and run
/// once per rule at `playpen check` over patterns of a handful of segments.
fn reachable(segments: &[Segment], fixed: &[&str], partial: &str) -> bool {
    let Some((first, rest)) = fixed.split_first() else {
        // Every whole segment is consumed. What is left must match one segment beginning with
        // `partial` followed by segments this chooses — and segments it chooses satisfy whatever
        // comes after, since a literal takes its own text and `*` and `**` take anything. So only
        // the pattern's next segment can refuse, and only by being a literal `partial` rules out.
        return match segments.first() {
            None => false,
            Some(Segment::Any | Segment::One) => true,
            Some(Segment::Literal(literal)) => literal.starts_with(partial),
        };
    };
    match segments.split_first() {
        // The path has a segment the pattern has run out of.
        None => false,
        Some((Segment::Literal(literal), rest_of_pattern)) => {
            literal == first && reachable(rest_of_pattern, rest, partial)
        }
        Some((Segment::One, rest_of_pattern)) => reachable(rest_of_pattern, rest, partial),
        // Zero segments, or this one and then the same `**` again.
        Some((Segment::Any, rest_of_pattern)) => {
            reachable(rest_of_pattern, fixed, partial) || reachable(segments, rest, partial)
        }
    }
}

impl TryFrom<String> for Glob {
    type Error = String;

    fn try_from(pattern: String) -> Result<Self, Self::Error> {
        Self::parse(&pattern).map_err(|why| format!("{pattern:?} is not a path glob: {why}"))
    }
}

impl From<Glob> for String {
    fn from(glob: Glob) -> Self {
        glob.pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(pattern: &str) -> Glob {
        Glob::parse(pattern).unwrap_or_else(|why| panic!("{pattern:?}: {why}"))
    }

    /// `*` is exactly one segment: never zero, never two, and never part of one.
    #[test]
    fn one_star_matches_exactly_one_segment() {
        let g = glob("/repos/*/*/pulls");
        assert!(g.matches("/repos/firefly/playpen/pulls"));
        assert!(!g.matches("/repos/firefly/pulls"), "`*` matched nothing");
        assert!(
            !g.matches("/repos/firefly/playpen/extra/pulls"),
            "`*` matched two segments"
        );
        assert!(!g.matches("/repos/firefly/playpen/pulls/1"));
    }

    /// `**` is zero or more, so it matches at the end and in the middle alike.
    #[test]
    fn two_stars_match_zero_or_more_segments() {
        let g = glob("/repos/*/*/**");
        assert!(g.matches("/repos/a/b"), "`**` matched zero segments");
        assert!(g.matches("/repos/a/b/issues"));
        assert!(g.matches("/repos/a/b/issues/1/comments"));
        assert!(!g.matches("/repos/a"));
        let middle = glob("/a/**/z");
        assert!(middle.matches("/a/z"));
        assert!(middle.matches("/a/b/z"));
        assert!(middle.matches("/a/b/c/z"));
        assert!(!middle.matches("/a/b/c"));
        // The bookmark is retried as far as it needs to go, including past a decoy.
        assert!(middle.matches("/a/z/b/z"));
    }

    /// The edges: the root, a trailing separator, an empty segment, and a pattern of `**` alone.
    #[test]
    fn the_edges_match_as_stated() {
        assert!(glob("/").matches("/"));
        assert!(!glob("/").matches("/a"));
        assert!(glob("/**").matches("/"));
        assert!(glob("/**").matches("/a/b/c"));
        assert!(glob("/v1/messages").matches("/v1/messages"));
        assert!(!glob("/v1/messages").matches("/v1/messages/"));
        assert!(glob("/v1/messages/").matches("/v1/messages/"));
        // A relative path is not host-absolute, so nothing matches it.
        assert!(!glob("/**").matches("v1/messages"));
        assert!(!glob("/**").matches(""));
    }

    /// Anything richer than the two tokens is refused, naming what made it so.
    #[test]
    fn a_richer_pattern_is_refused() {
        for pattern in [
            "/a/{b,c}", "/a/[bc]", "/a/b?", "/a/(b|c)", "/^a", "/a$", "/a\\*b", "/a|b",
        ] {
            let why = Glob::parse(pattern).expect_err(pattern);
            assert!(!why.is_empty(), "{pattern}");
        }
        // `*` mixed into a segment is not the token: it is a segment that happens to hold one.
        for pattern in ["/a/b*", "/a/*b", "/a/***", "/*x/b"] {
            let why = Glob::parse(pattern).expect_err(pattern);
            assert!(why.contains("whole segments"), "{pattern}: {why}");
        }
        let why = Glob::parse("repos/a").expect_err("relative");
        assert!(why.contains("host-absolute"), "{why}");
    }

    /// A rule is satisfiable under a prefix when some path with that prefix matches it. The
    /// prefix is a literal string, so it may stop mid-segment.
    #[test]
    fn satisfiability_is_about_the_paths_the_prefix_leaves() {
        // The coarsest prefix leaves every path, so everything is satisfiable under it.
        for pattern in ["/", "/**", "/v1/messages", "/repos/*/*/**"] {
            assert!(glob(pattern).satisfiable_under("/"), "{pattern}");
        }
        // A prefix that fixes whole segments rules out every pattern that disagrees with them.
        let under = |pattern: &str, prefix: &str| glob(pattern).satisfiable_under(prefix);
        assert!(under("/repos/*/*/**", "/repos/firefly/"));
        assert!(under("/repos/**", "/repos/firefly/playpen"));
        assert!(!under("/v1/messages", "/repos/firefly/"));
        assert!(!under("/repos/a/**", "/repos/b/"));
        // A prefix stopping mid-segment: a literal segment must be able to extend it.
        assert!(under("/repos/firefly-engineering/**", "/repos/firefly"));
        assert!(!under("/repos/other/**", "/repos/firefly"));
        // `*` and `**` extend any partial segment.
        assert!(under("/repos/*/**", "/repos/firefly"));
        assert!(under("/**", "/repos/firefly"));
        // A pattern shorter than the prefix's whole segments can still reach it through `**`.
        assert!(under("/**/pulls", "/repos/a/b/"));
        assert!(!under("/repos", "/repos/a/"));
        // `/repos` fixes one segment and stops after it, so a path under it needs one more.
        assert!(under("/repos/*", "/repos/"));
        assert!(!under("/repos", "/repos/"));
    }

    /// The naive reading of the semantics, as a reference: `**` tries every split, `*` takes one
    /// segment, a literal takes itself. Exponential, and only ever run over tiny inputs.
    fn reference(segments: &[Segment], parts: &[&str]) -> bool {
        match segments.split_first() {
            None => parts.is_empty(),
            Some((Segment::Any, rest)) => {
                (0..=parts.len()).any(|take| reference(rest, &parts[take..]))
            }
            Some((Segment::One, rest)) => !parts.is_empty() && reference(rest, &parts[1..]),
            Some((Segment::Literal(literal), rest)) => {
                parts.first() == Some(&literal.as_str()) && reference(rest, &parts[1..])
            }
        }
    }

    /// The matcher is total, and it is the semantics: over every pattern and every path that two
    /// segment alphabets make up to length three, it returns — without panicking — exactly what
    /// the naive reading says.
    #[test]
    fn the_matcher_is_total_and_agrees_with_the_semantics() {
        let tokens = ["a", "b", "*", "**"];
        let mut patterns: Vec<String> = Vec::new();
        for length in 0..=3 {
            patterns.extend(combinations(&tokens, length).into_iter().map(|parts| {
                let mut pattern = String::from("/");
                pattern.push_str(&parts.join("/"));
                pattern
            }));
        }
        let mut paths: Vec<String> = Vec::new();
        for length in 0..=3 {
            paths.extend(
                combinations(&["a", "b", "c"], length)
                    .into_iter()
                    .map(|parts| {
                        let mut path = String::from("/");
                        path.push_str(&parts.join("/"));
                        path
                    }),
            );
        }
        assert!(patterns.len() > 80 && paths.len() > 35, "a thin alphabet");
        let mut checked = 0usize;
        for pattern in &patterns {
            let g = glob(pattern);
            for path in &paths {
                let parts: Vec<&str> = path
                    .strip_prefix('/')
                    .expect("host-absolute")
                    .split('/')
                    .collect();
                assert_eq!(
                    g.matches(path),
                    reference(&g.segments, &parts),
                    "{pattern} against {path}"
                );
                checked += 1;
                // Satisfiability never refuses a rule a path with that prefix does match: an
                // over-approximation merely leaves a rule set that allows nothing, which fails
                // closed, while an under-approximation refuses a policy that was fine. Every
                // prefix of a matching path witnesses satisfiability, mid-segment ones included.
                if g.matches(path) {
                    for end in 1..=path.len() {
                        let prefix = &path[..end];
                        assert!(
                            g.satisfiable_under(prefix),
                            "{pattern} matches {path} but was called unsatisfiable \
                             under {prefix}"
                        );
                    }
                }
            }
        }
        assert_eq!(checked, patterns.len() * paths.len());
    }

    /// Every sequence of `tokens` of exactly `length`.
    fn combinations(tokens: &[&str], length: usize) -> Vec<Vec<String>> {
        if length == 0 {
            return vec![Vec::new()];
        }
        let shorter = combinations(tokens, length - 1);
        shorter
            .iter()
            .flat_map(|prefix| {
                tokens.iter().map(move |token| {
                    let mut longer = prefix.clone();
                    longer.push((*token).to_owned());
                    longer
                })
            })
            .collect()
    }

    /// The pattern as written is what survives a round trip, because that is what the manifest
    /// and `explain` state.
    #[test]
    fn it_round_trips_as_the_pattern_it_was_written_as() {
        let text = serde_json::to_string(&glob("/repos/*/*/**")).expect("JSON");
        assert_eq!(text, "\"/repos/*/*/**\"");
        let back: Glob = serde_json::from_str(&text).expect("reads back");
        assert_eq!(back.as_str(), "/repos/*/*/**");
        assert!(back.matches("/repos/a/b/c"));
        let why = serde_json::from_str::<Glob>("\"/a/{b}\"").expect_err("refused");
        assert!(why.to_string().contains("is not a path glob"), "{why}");
    }
}
