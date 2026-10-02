//! The refusal line ([spec §14.3]): one line on stderr, then exit `125`.
//!
//! [spec §14.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#143-the-refusal-line

use std::fmt;
use std::io::Write;

use crate::code::Code;

/// Exit status reserved for "playpen did not run the agent".
pub const EXIT_REFUSED: i32 = 125;

/// playpen declined to run the agent, for one stable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: Code,
    message: String,
}

impl Refusal {
    /// A refusal carrying a human sentence that names the offending value.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Write the refusal line to stderr in a single write.
    pub fn emit(&self) {
        let line = format!("{self}\n");
        // Nothing useful can be done if stderr itself is gone.
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "playpen: {}: ", self.code)?;
        // A value can carry any byte; the line must stay one line.
        for c in self.message.chars() {
            if c.is_control() {
                write!(f, "{}", c.escape_default())?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prefix_code_and_message() {
        let r = Refusal::new(Code::CwdUngranted, "cwd /tmp is outside every granted root");
        assert_eq!(
            r.to_string(),
            "playpen: refusal.cwd.ungranted: cwd /tmp is outside every granted root"
        );
    }

    #[test]
    fn control_characters_never_break_the_line() {
        let r = Refusal::new(Code::RootMissing, "root /a\nb\r\tc is missing");
        let line = r.to_string();
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(line.ends_with(r"root /a\nb\r\tc is missing"));
    }
}
