//! TOML string literals for config text that tain prints (`tain check`,
//! `tain import`), so both stay valid TOML whatever the values contain.

use std::fmt::Write as _;

/// TOML basic string; every control character is escaped.
pub(crate) fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => write!(out, "\\u{:04X}", u32::from(c)).unwrap(),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// TOML array of basic strings.
pub(crate) fn toml_string_list(v: &[String]) -> String {
    let items: Vec<String> = v.iter().map(|s| toml_string(s)).collect();
    format!("[{}]", items.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_backslashes_and_every_control_character() {
        assert_eq!(toml_string("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(toml_string("\n\t"), r#""\n\t""#);
        assert_eq!(
            toml_string("\u{0}\u{7}\u{1b}\u{7f}\u{85}"),
            r#""\u0000\u0007\u001B\u007F\u0085""#
        );
        assert_eq!(toml_string("ünï"), "\"ünï\"");
    }

    #[test]
    fn every_escaped_string_parses_back_unchanged() {
        let all: String = (0u32..0x100).filter_map(char::from_u32).collect();
        let doc = format!("v = {}", toml_string(&all));
        let table: ::toml::Table = ::toml::from_str(&doc).unwrap();
        assert_eq!(table["v"].as_str(), Some(all.as_str()));
    }

    #[test]
    fn lists_join_with_comma_space() {
        assert_eq!(toml_string_list(&[]), "[]");
        assert_eq!(
            toml_string_list(&["a".into(), "b\u{1}".into()]),
            r#"["a", "b\u0001"]"#
        );
    }
}
