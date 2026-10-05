//! The parser contract ([spec §10.2]): what makes a text a policy document, and a refusal that
//! names file, line and column when it is not one.
//!
//! serde-saphyr deserialises the types, and refuses an unknown key, a mistyped value and a
//! malformed document itself. What it cannot see, a pass over the YAML event stream checks first,
//! with the same parser underneath, so both passes agree on every position:
//!
//! - a second document (`---`);
//! - an explicit tag other than `!area`, which serde-saphyr would otherwise drop;
//! - a NUL in any scalar, which a `String` accepts;
//! - where each anchor sits and where a merge key uses it. serde-saphyr names only the definition
//!   site of a key that arrived through a merge, and the spec asks for both, so the use site is
//!   recovered from here ([`Shape::merge_site`]).
//!
//! [spec §10.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#102-syntax-and-strictness

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use serde::Deserialize;
use serde_saphyr::granit_parser::{Event, Marker, Parser, ScalarStyle, Tag};
use serde_saphyr::{
    DefaultMessageFormatter, Error, Localizer, Location, RenderOptions, SnippetMode, Spanned,
};

use super::{Policy, VERSION};
use crate::code::Code;
use crate::refusal::Refusal;

/// Parse `text`, read from `origin`, as a policy document.
pub(super) fn parse(text: &str, origin: &Path) -> Result<Policy, Refusal> {
    let shape = Shape::scan(text, origin)?;
    // The version first, on its own: a document written for another version is refused as that,
    // not for whichever of its keys this version happens not to know.
    let head: Head = deserialize(text).map_err(|e| shape.refusal(&e, origin))?;
    if head.version.value != VERSION {
        let at = Pos::of_location(&head.version.referenced);
        return Err(Refusal::new(
            Code::PolicyVersion,
            format!(
                "{}: version {} is not one this playpen reads (it reads version {VERSION})",
                Site { origin, at },
                head.version.value,
            ),
        ));
    }
    deserialize(text).map_err(|e| shape.refusal(&e, origin))
}

/// The one key read before the rest.
#[derive(Deserialize)]
struct Head {
    version: Spanned<u32>,
}

fn deserialize<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, Error> {
    let options = serde_saphyr::options! {
        // `no` is a string in YAML 1.2, so `mode: no` is an invalid variant, never `false`.
        strict_booleans: true,
        // The refusal is one line; a snippet would be several.
        with_snippet: false,
    };
    serde_saphyr::from_str_with_options(text, options)
}

/// A position in the source: line and column, both 1-based, as serde-saphyr reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Pos {
    line: u64,
    column: u64,
}

impl Pos {
    fn of(marker: &Marker) -> Self {
        Self {
            line: marker.line() as u64,
            // The event parser counts columns from 0, serde-saphyr from 1.
            column: marker.col() as u64 + 1,
        }
    }

    /// `None` for serde-saphyr's unknown location.
    fn of_location(location: &Location) -> Option<Self> {
        (location.line() > 0).then(|| Self {
            line: location.line(),
            column: location.column(),
        })
    }
}

/// `file:line:column`, or the file alone where the position is unknown.
struct Site<'a> {
    origin: &'a Path,
    at: Option<Pos>,
}

impl fmt::Display for Site<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.at {
            Some(Pos { line, column }) => write!(f, "{}:{line}:{column}", self.origin.display()),
            None => write!(f, "{}", self.origin.display()),
        }
    }
}

/// Where `value` was written in the policy read from `origin`: its use site, and its definition
/// site too where an alias or a merge key brought it there.
pub(super) fn written_at<T>(origin: &Path, value: &Spanned<T>) -> String {
    let used = Pos::of_location(&value.referenced);
    let defined = Pos::of_location(&value.defined);
    match (used, defined) {
        (Some(used), Some(defined)) if used != defined => format!(
            "{} (defined at {})",
            Site {
                origin,
                at: Some(used)
            },
            Site {
                origin,
                at: Some(defined)
            },
        ),
        (used, defined) => Site {
            origin,
            at: used.or(defined),
        }
        .to_string(),
    }
}

/// An anchored node: the half-open range of source it covers, and whether it was defined under
/// `definitions:`.
struct Anchor {
    start: Pos,
    end: Pos,
    in_definitions: bool,
}

/// A merge key using an anchor: `<<: *a`, or one alias of `<<: [*a, *b]`.
struct Merge {
    anchor: usize,
    /// The alias, at the use site.
    at: Pos,
    in_definitions: bool,
}

/// What the event pass learned that deserialisation needs: where every anchor is, and where each
/// was merged, in document order.
#[derive(Default)]
struct Shape {
    anchors: HashMap<usize, Anchor>,
    merges: Vec<Merge>,
}

/// What an open container is, while the pass is inside it.
struct Frame {
    anchor: usize,
    start: Pos,
    in_definitions: bool,
    kind: FrameKind,
}

enum FrameKind {
    Map {
        /// The document's top-level mapping, whose `definitions` key is the free-form one.
        root: bool,
        /// Whether the next node is a key.
        at_key: bool,
        /// The key whose value comes next.
        key: Key,
    },
    Seq {
        /// The value of a merge key, so each alias in it is a merge.
        merging: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Merge,
    Definitions,
    Other,
}

/// Where a node sits, decided as it starts.
struct Context {
    is_key: bool,
    merging: bool,
    in_definitions: bool,
}

impl Shape {
    fn scan(text: &str, origin: &Path) -> Result<Self, Refusal> {
        let mut shape = Shape::default();
        let mut stack: Vec<Frame> = Vec::new();
        let mut documents = 0;
        for event in Parser::new_from_str(text) {
            let (event, span) = event.map_err(|e| {
                let at = Some(Pos::of(e.marker()));
                Refusal::new(
                    Code::PolicySyntax,
                    format!("{}: {}", Site { origin, at }, e.info()),
                )
            })?;
            let start = Pos::of(&span.start);
            let refuse = |code, what: &str| {
                let at = Some(Pos::of(span.tag_start().as_ref().unwrap_or(&span.start)));
                Err(Refusal::new(
                    code,
                    format!("{}: {what}", Site { origin, at }),
                ))
            };
            match event {
                Event::DocumentStart(..) => {
                    documents += 1;
                    if documents > 1 {
                        return refuse(
                            Code::PolicySyntax,
                            "a second document begins here; a policy is one document",
                        );
                    }
                }
                Event::Alias(anchor) => {
                    let context = context(&stack);
                    if context.merging {
                        shape.merges.push(Merge {
                            anchor,
                            at: start,
                            in_definitions: context.in_definitions,
                        });
                    }
                    complete(&mut stack, Key::Other);
                }
                Event::Scalar(value, style, anchor, tag) => {
                    if let Some(tag) = foreign(tag.as_deref()) {
                        return refuse(Code::PolicyTag, &tag_refusal(tag));
                    }
                    if value.contains('\0') {
                        return refuse(Code::PolicyType, "a value holds a NUL");
                    }
                    let context = context(&stack);
                    if anchor != 0 {
                        shape.anchor(anchor, start, Pos::of(&span.end), context.in_definitions);
                    }
                    let key = match (context.is_key, style, tag, value.as_ref()) {
                        (true, ScalarStyle::Plain, None, "<<") => Key::Merge,
                        (true, _, _, "definitions") => Key::Definitions,
                        _ => Key::Other,
                    };
                    complete(&mut stack, key);
                }
                Event::SequenceStart(_, anchor, ref tag)
                | Event::MappingStart(_, anchor, ref tag) => {
                    if let Some(tag) = foreign(tag.as_deref()) {
                        return refuse(Code::PolicyTag, &tag_refusal(tag));
                    }
                    let context = context(&stack);
                    let kind = match event {
                        Event::SequenceStart(..) => FrameKind::Seq {
                            merging: context.merging,
                        },
                        _ => FrameKind::Map {
                            root: stack.is_empty(),
                            at_key: true,
                            key: Key::Other,
                        },
                    };
                    stack.push(Frame {
                        anchor,
                        start,
                        in_definitions: context.in_definitions,
                        kind,
                    });
                }
                Event::SequenceEnd | Event::MappingEnd => {
                    if let Some(frame) = stack.pop()
                        && frame.anchor != 0
                    {
                        let end = Pos::of(&span.end);
                        shape.anchor(frame.anchor, frame.start, end, frame.in_definitions);
                    }
                    complete(&mut stack, Key::Other);
                }
                // Stream and document boundaries, and comments, carry nothing the pass checks.
                _ => {}
            }
        }
        Ok(shape)
    }

    fn anchor(&mut self, id: usize, start: Pos, end: Pos, in_definitions: bool) {
        self.anchors.insert(
            id,
            Anchor {
                start,
                end,
                in_definitions,
            },
        );
    }

    /// The merge key that brought the node at `at` into a typed position, if a merge did.
    ///
    /// serde-saphyr reports such a node at its definition alone. An anchor defined under
    /// `definitions:` is never deserialised there, so a refusal located inside one arose where it
    /// was merged: at the first merge of it outside `definitions:`, in document order, since
    /// deserialisation is in document order and stops at the first refusal. A merge that is itself
    /// inside `definitions:` is followed outward to wherever its own anchor was merged.
    ///
    /// An anchor defined in a typed position is deserialised there first, so a refusal inside it
    /// is truly at its definition, and is left there. That misses only an anchor merged into a
    /// position of a different type, and the whole recovery goes once serde-saphyr attaches the use
    /// site itself ([#125]).
    ///
    /// [#125]: https://github.com/firefly-engineering/playpen/issues/125
    fn merge_site(&self, mut at: Pos) -> Option<Pos> {
        // Each step moves to a merge earlier in the document, so the walk ends; the bound is
        // only a guard.
        for _ in 0..=self.merges.len() {
            let mut using = self.merges.iter().filter(|merge| {
                self.anchors.get(&merge.anchor).is_some_and(|anchor| {
                    anchor.in_definitions && anchor.start <= at && at < anchor.end
                })
            });
            let first = using.next()?;
            match std::iter::once(first)
                .chain(using)
                .find(|merge| !merge.in_definitions)
            {
                Some(merge) => return Some(merge.at),
                None => at = first.at,
            }
        }
        None
    }

    /// The refusal for `err`, raised deserialising the document read from `origin`.
    fn refusal(&self, err: &Error, origin: &Path) -> Refusal {
        let err = err.without_snippet();
        let (code, message) = match err {
            // serde-saphyr flattens an error raised through an alias into its message.
            Error::AliasError { msg, .. } => (alias_code(msg), msg.clone()),
            err => (code(err), bare(err)),
        };
        let locations = err.locations();
        let defined = locations.and_then(|l| Pos::of_location(&l.defined_location));
        let used = match locations.and_then(|l| Pos::of_location(&l.reference_location)) {
            Some(used) if Some(used) != defined => Some(used),
            _ => defined.and_then(|defined| self.merge_site(defined)),
        };
        let at = match used {
            Some(used) => format!(
                "{} (defined at {})",
                Site {
                    origin,
                    at: Some(used)
                },
                Site {
                    origin,
                    at: defined
                },
            ),
            None => Site {
                origin,
                at: defined,
            }
            .to_string(),
        };
        Refusal::new(code, format!("{at}: {message}"))
    }
}

/// Where the node starting now sits, from the innermost open container.
fn context(stack: &[Frame]) -> Context {
    let Some(parent) = stack.last() else {
        return Context {
            is_key: false,
            merging: false,
            in_definitions: false,
        };
    };
    match parent.kind {
        FrameKind::Map { at_key: true, .. } => Context {
            is_key: true,
            merging: false,
            in_definitions: parent.in_definitions,
        },
        FrameKind::Map { root, key, .. } => Context {
            is_key: false,
            merging: key == Key::Merge,
            in_definitions: parent.in_definitions || (root && key == Key::Definitions),
        },
        FrameKind::Seq { merging } => Context {
            is_key: false,
            merging,
            in_definitions: parent.in_definitions,
        },
    }
}

/// A node just ended inside the innermost container. In a mapping, a key is followed by its value
/// and a value by the next key; `key` says which key it was, if it was one.
fn complete(stack: &mut [Frame], key: Key) {
    if let Some(Frame {
        kind:
            FrameKind::Map {
                at_key,
                key: current,
                ..
            },
        ..
    }) = stack.last_mut()
    {
        if *at_key {
            *current = key;
        }
        *at_key = !*at_key;
    }
}

/// `tag`, unless it is absent or playpen's own `!area`.
fn foreign(tag: Option<&Tag>) -> Option<&Tag> {
    tag.filter(|tag| !(tag.handle() == "!" && tag.suffix() == "area"))
}

fn tag_refusal(tag: &Tag) -> String {
    format!(
        "explicit tag {}{} is not one a policy may carry; the only one is !area",
        tag.original_handle(),
        tag.suffix()
    )
}

/// The code of an error serde-saphyr raised directly.
fn code(err: &Error) -> Code {
    match err {
        Error::SerdeUnknownField { .. } => Code::PolicyUnknownField,
        Error::SerdeInvalidType { .. }
        | Error::SerdeInvalidValue { .. }
        | Error::SerdeUnknownVariant { .. }
        | Error::SerdeMissingField { .. }
        | Error::Message { .. }
        | Error::Unexpected { .. }
        | Error::InvalidScalar { .. }
        | Error::InvalidBooleanStrict { .. }
        | Error::InvalidCharNull { .. }
        | Error::NullIntoString { .. }
        | Error::NonFiniteFloat { .. }
        | Error::TaggedEnumMismatch { .. }
        | Error::ExternallyTaggedEnumExpectedScalarOrMapping { .. }
        | Error::ExpectedStringKeyForExternallyTaggedEnum { .. }
        | Error::UnexpectedValueForUnitEnumVariant { .. } => Code::PolicyType,
        _ => Code::PolicySyntax,
    }
}

/// The code of an error raised through an alias, which serde-saphyr hands back as its rendered
/// message alone.
///
/// The kind is read back from the message's opening words, which is the one place playpen leans
/// on serde-saphyr's wording: the dependency is pinned to an exact version for it, and the tests
/// raise each kind through an alias, so a release that rewords them fails here rather than
/// misfiling a refusal. Only two kinds can arise in replayed events — the pass above has already
/// refused every syntax error, tag and NUL — so anything that is not an unknown field is a type
/// refusal. The reading goes when serde-saphyr keeps the inner error ([#125]).
///
/// [#125]: https://github.com/firefly-engineering/playpen/issues/125
fn alias_code(message: &str) -> Code {
    if message.starts_with("unknown field") {
        Code::PolicyUnknownField
    } else {
        Code::PolicyType
    }
}

/// `err`'s message without serde-saphyr's own position suffix: the refusal places it.
fn bare(err: &Error) -> String {
    struct Unplaced;
    impl Localizer for Unplaced {
        fn attach_location<'a>(&self, base: Cow<'a, str>, _: Location) -> Cow<'a, str> {
            base
        }
    }
    let formatter = DefaultMessageFormatter.with_localizer(&Unplaced);
    let mut options = RenderOptions::new(&formatter);
    options.snippets = SnippetMode::Off;
    err.render_with_options(options)
}
