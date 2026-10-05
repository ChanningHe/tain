//! Streaming deb822 paragraph parser: one paragraph in memory at a time, since a
//! `Packages` file can hold hundreds of thousands of entries.

use std::io::{self, BufRead};

/// Per-line byte cap against hostile upstreams; real lines stay well under 1 MiB.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// One deb822 paragraph. Field lookup is case-insensitive, as in apt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Paragraph {
    // Insertion order; repeated names are kept.
    fields: Vec<(String, String)>,
    // 1-indexed line of the first field.
    start_line: usize,
}

impl Paragraph {
    #[must_use]
    pub fn start_line(&self) -> usize {
        self.start_line
    }

    /// Return the first value matching `name` (case-insensitive).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Iterate every field in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of fields (including duplicates).
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// True iff the field is present (case-insensitive).
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Test-only constructor. Real paragraphs come from `Deb822Reader`.
    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: Vec<(&str, &str)>) -> Self {
        Self {
            fields: pairs
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
            start_line: 0,
        }
    }
}

/// Pull-based reader yielding one paragraph at a time.
pub struct Deb822Reader<R: BufRead> {
    reader: R,
    line_buf: String,
    // One-line pushback.
    peeked: Option<Line>,
    line_no: usize,
}

#[derive(Debug, Clone)]
struct Line {
    /// Raw content with the trailing `\n` / `\r\n` stripped.
    text: String,
    /// 1-indexed source line number.
    number: usize,
}

impl<R: BufRead> Deb822Reader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            line_buf: String::new(),
            peeked: None,
            line_no: 0,
        }
    }

    /// Line number of the last line read.
    #[must_use]
    pub fn line_no(&self) -> usize {
        self.line_no
    }

    /// Read the next paragraph.
    ///
    /// # Errors
    ///
    /// I/O, invalid UTF-8, overlong lines, or malformed headers (see [`ParseError`]).
    pub fn read_paragraph(&mut self) -> Result<Option<Paragraph>, ParseError> {
        let first = loop {
            let Some(line) = self.next_line()? else {
                return Ok(None);
            };
            if line.text.is_empty() || line.text.starts_with('#') {
                continue;
            }
            break line;
        };

        let start_line = first.number;
        let mut fields: Vec<(String, String)> = Vec::new();
        let mut current: Option<(String, String)> = None;
        let mut line = first;

        loop {
            if line.text.is_empty() {
                break;
            }
            if line.text.starts_with('#') {
                // Comment lines are dropped without breaking continuation.
            } else if is_continuation(&line.text) {
                let content_raw = &line.text[1..];
                let content = if content_raw == "." { "" } else { content_raw };
                match current.as_mut() {
                    Some((_, v)) => {
                        v.push('\n');
                        v.push_str(content);
                    }
                    None => {
                        return Err(ParseError::ContinuationWithoutField { line: line.number });
                    }
                }
            } else {
                if let Some(f) = current.take() {
                    fields.push(f);
                }
                let (name, value) = parse_header(&line.text, line.number)?;
                current = Some((name, value));
            }

            match self.next_line()? {
                Some(l) => line = l,
                None => break,
            }
        }

        if let Some(f) = current.take() {
            fields.push(f);
        }

        Ok(Some(Paragraph { fields, start_line }))
    }

    fn next_line(&mut self) -> Result<Option<Line>, ParseError> {
        if let Some(l) = self.peeked.take() {
            return Ok(Some(l));
        }
        self.line_buf.clear();
        // Byte-at-a-time so a hostile newline-free line cannot exceed `MAX_LINE_BYTES`.
        loop {
            let mut byte = [0u8; 1];
            let n = self.reader.read(&mut byte).map_err(ParseError::Io)?;
            if n == 0 {
                if self.line_buf.is_empty() {
                    return Ok(None);
                }
                break;
            }
            if self.line_buf.len() >= MAX_LINE_BYTES {
                return Err(ParseError::LineTooLong {
                    line: self.line_no + 1,
                    limit: MAX_LINE_BYTES,
                });
            }
            let ch = match byte[0] {
                b'\n' => break,
                b'\r' => continue,
                b if b.is_ascii() => b as char,
                _ => {
                    // Non-UTF-8 input is rejected here.
                    self.decode_multibyte(byte[0])?
                }
            };
            self.line_buf.push(ch);
        }
        self.line_no += 1;
        let text = self.line_buf.clone();
        self.line_buf.clear();
        Ok(Some(Line {
            text,
            number: self.line_no,
        }))
    }

    /// Decode one multibyte UTF-8 char starting with `first`.
    fn decode_multibyte(&mut self, first: u8) -> Result<char, ParseError> {
        let expected = if first & 0b1110_0000 == 0b1100_0000 {
            2
        } else if first & 0b1111_0000 == 0b1110_0000 {
            3
        } else if first & 0b1111_1000 == 0b1111_0000 {
            4
        } else {
            return Err(ParseError::InvalidUtf8 {
                line: self.line_no + 1,
            });
        };
        let mut buf = [0u8; 4];
        buf[0] = first;
        for slot in buf.iter_mut().take(expected).skip(1) {
            let mut b = [0u8; 1];
            let n = self.reader.read(&mut b).map_err(ParseError::Io)?;
            if n == 0 || (b[0] & 0b1100_0000) != 0b1000_0000 {
                return Err(ParseError::InvalidUtf8 {
                    line: self.line_no + 1,
                });
            }
            *slot = b[0];
        }
        match std::str::from_utf8(&buf[..expected]) {
            Ok(s) => Ok(s.chars().next().unwrap_or('\u{FFFD}')),
            Err(_) => Err(ParseError::InvalidUtf8 {
                line: self.line_no + 1,
            }),
        }
    }
}

impl<R: BufRead> Iterator for Deb822Reader<R> {
    type Item = Result<Paragraph, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read_paragraph() {
            Ok(Some(p)) => Some(Ok(p)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

fn is_continuation(line: &str) -> bool {
    matches!(line.as_bytes().first(), Some(b' ' | b'\t'))
}

fn parse_header(line: &str, line_no: usize) -> Result<(String, String), ParseError> {
    let colon = line.find(':').ok_or_else(|| ParseError::MissingColon {
        line: line_no,
        snippet: line.to_owned(),
    })?;
    let name = &line[..colon];
    validate_field_name(name).map_err(|reason| ParseError::MalformedFieldName {
        line: line_no,
        name: name.to_owned(),
        reason,
    })?;
    // deb822: one optional SP/HT after `:`; further whitespace belongs to the value.
    let mut value = &line[colon + 1..];
    if matches!(value.as_bytes().first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    Ok((name.to_owned(), value.to_owned()))
}

/// Field name rules (deb822 = RFC 5322 tokens minus `:`).
fn validate_field_name(name: &str) -> Result<(), FieldNameProblem> {
    if name.is_empty() {
        return Err(FieldNameProblem::Empty);
    }
    for c in name.chars() {
        let bad = c.is_ascii_control() || c == ' ' || c == '\t' || c == ':' || (c as u32) > 0x7E;
        if bad {
            return Err(FieldNameProblem::InvalidChar(c));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("line {line}: field header has no `:`: `{snippet}`")]
    MissingColon { line: usize, snippet: String },
    #[error("line {line}: field name `{name}` is invalid ({reason})")]
    MalformedFieldName {
        line: usize,
        name: String,
        reason: FieldNameProblem,
    },
    #[error("line {line}: continuation line has no field to attach to")]
    ContinuationWithoutField { line: usize },
    #[error("line {line}: exceeds maximum line length ({limit} bytes)")]
    LineTooLong { line: usize, limit: usize },
    #[error("line {line}: input is not valid UTF-8")]
    InvalidUtf8 { line: usize },
    #[error("I/O: {0}")]
    Io(#[source] io::Error),
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum FieldNameProblem {
    #[error("empty")]
    Empty,
    #[error("invalid character `{0:?}`")]
    InvalidChar(char),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse_all(input: &str) -> Vec<Paragraph> {
        Deb822Reader::new(Cursor::new(input))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("parse failed: {e}\nInput:\n{input}"))
    }

    #[test]
    fn empty_input_yields_no_paragraphs() {
        assert!(parse_all("").is_empty());
    }

    #[test]
    fn single_field_single_paragraph() {
        let p = parse_all("Package: nginx\n");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].get("Package"), Some("nginx"));
    }

    #[test]
    fn get_is_case_insensitive() {
        let p = parse_all("Package: nginx\n");
        assert_eq!(p[0].get("Package"), Some("nginx"));
        assert_eq!(p[0].get("package"), Some("nginx"));
        assert_eq!(p[0].get("PACKAGE"), Some("nginx"));
    }

    #[test]
    fn multiple_fields_preserve_order() {
        let input = "Package: nginx\nVersion: 1.24\nArchitecture: amd64\n";
        let p = parse_all(input);
        let names: Vec<_> = p[0].iter().map(|(k, _)| k).collect();
        assert_eq!(names, vec!["Package", "Version", "Architecture"]);
    }

    #[test]
    fn two_paragraphs_separated_by_blank() {
        let input = "Package: a\nVersion: 1\n\nPackage: b\nVersion: 2\n";
        let p = parse_all(input);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].get("Package"), Some("a"));
        assert_eq!(p[1].get("Package"), Some("b"));
    }

    #[test]
    fn trailing_newline_optional() {
        let input = "Package: nginx\nVersion: 1.24";
        let p = parse_all(input);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].get("Version"), Some("1.24"));
    }

    #[test]
    fn crlf_line_endings_handled() {
        let input = "Package: nginx\r\nVersion: 1.24\r\n";
        let p = parse_all(input);
        assert_eq!(p[0].get("Version"), Some("1.24"));
    }

    #[test]
    fn leading_blank_lines_skipped() {
        let input = "\n\n\nPackage: nginx\n";
        let p = parse_all(input);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn multiple_blank_lines_between_paragraphs() {
        let input = "Package: a\n\n\n\nPackage: b\n";
        let p = parse_all(input);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn value_with_no_leading_space_after_colon() {
        let p = parse_all("Package:nginx\n");
        assert_eq!(p[0].get("Package"), Some("nginx"));
    }

    #[test]
    fn value_with_extra_leading_whitespace_kept_after_first() {
        let p = parse_all("Package:  nginx\n");
        assert_eq!(p[0].get("Package"), Some(" nginx"));
    }

    #[test]
    fn tab_after_colon_stripped_like_space() {
        let p = parse_all("Package:\tnginx\n");
        assert_eq!(p[0].get("Package"), Some("nginx"));
    }

    #[test]
    fn continuation_appended_with_newline_separator() {
        let input = "Description: a short line\n more detail here\n even more\n";
        let p = parse_all(input);
        assert_eq!(
            p[0].get("Description"),
            Some("a short line\nmore detail here\neven more")
        );
    }

    #[test]
    fn dot_continuation_is_empty_line() {
        let input = "Description: intro\n .\n after blank\n";
        let p = parse_all(input);
        assert_eq!(p[0].get("Description"), Some("intro\n\nafter blank"));
    }

    #[test]
    fn checksum_block_style_multiline() {
        let input = "\
SHA256:
 3183eff2f4e8e3a51e0a9ffcb43e3f9be0000000000000000000000000000abcd 1158196 main/binary-i386/Packages
 4183eff2f4e8e3a51e0a9ffcb43e3f9be0000000000000000000000000000abcd 158196 main/binary-amd64/Packages
";
        let p = parse_all(input);
        let v = p[0].get("SHA256").unwrap();
        let lines: Vec<_> = v.split('\n').collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].is_empty());
        assert!(lines[1].starts_with("3183"));
        assert!(lines[2].starts_with("4183"));
    }

    #[test]
    fn tab_indented_continuation_supported() {
        let input = "Description: intro\n\tmore\n";
        let p = parse_all(input);
        assert_eq!(p[0].get("Description"), Some("intro\nmore"));
    }

    #[test]
    fn hash_comment_between_paragraphs_ignored() {
        let input = "# top comment\nPackage: a\n\n# mid comment\nPackage: b\n";
        let p = parse_all(input);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn hash_comment_inside_paragraph_dropped() {
        let input = "Package: a\n# comment mid-paragraph\nVersion: 1\n";
        let p = parse_all(input);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].get("Package"), Some("a"));
        assert_eq!(p[0].get("Version"), Some("1"));
    }

    #[test]
    fn missing_colon_rejected() {
        let input = "Package nginx\n";
        let err = Deb822Reader::new(Cursor::new(input))
            .read_paragraph()
            .unwrap_err();
        assert!(matches!(err, ParseError::MissingColon { line: 1, .. }));
    }

    #[test]
    fn space_in_field_name_rejected() {
        let input = "Bad name: whatever\n";
        let err = Deb822Reader::new(Cursor::new(input))
            .read_paragraph()
            .unwrap_err();
        assert!(matches!(
            err,
            ParseError::MalformedFieldName { line: 1, .. }
        ));
    }

    #[test]
    fn empty_field_name_rejected() {
        let input = ": value\n";
        let err = Deb822Reader::new(Cursor::new(input))
            .read_paragraph()
            .unwrap_err();
        assert!(matches!(
            err,
            ParseError::MalformedFieldName { line: 1, .. }
        ));
    }

    #[test]
    fn non_ascii_field_name_rejected() {
        let input = "Naïve: value\n";
        let err = Deb822Reader::new(Cursor::new(input))
            .read_paragraph()
            .unwrap_err();
        assert!(matches!(
            err,
            ParseError::MalformedFieldName { line: 1, .. }
        ));
    }

    #[test]
    fn continuation_without_field_rejected() {
        let input = "Package: a\n\n continuation-only-line\n";
        let mut r = Deb822Reader::new(Cursor::new(input));
        let first = r.read_paragraph().unwrap().unwrap();
        assert_eq!(first.get("Package"), Some("a"));
        let e = r.read_paragraph().unwrap_err();
        assert!(matches!(e, ParseError::ContinuationWithoutField { .. }));
    }

    #[test]
    fn line_number_reported_in_error() {
        let input = "\nPackage: ok\n\nBad name: x\n";
        let mut r = Deb822Reader::new(Cursor::new(input));
        let _ = r.read_paragraph().unwrap();
        let e = r.read_paragraph().unwrap_err();
        match e {
            ParseError::MalformedFieldName { line, .. } => {
                assert_eq!(line, 4, "expected line 4, got {line}");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn iterator_yields_ok_and_stops_at_eof() {
        let input = "Package: a\n\nPackage: b\n";
        let items: Vec<_> = Deb822Reader::new(Cursor::new(input)).collect();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(Result::is_ok));
    }

    #[test]
    fn iterator_after_eof_returns_none() {
        let input = "Package: a\n";
        let mut r = Deb822Reader::new(Cursor::new(input));
        let _ = r.next().unwrap().unwrap();
        assert!(r.next().is_none());
        assert!(r.next().is_none(), "EOF is sticky");
    }

    #[test]
    fn duplicate_field_name_kept_in_iter_but_get_returns_first() {
        let input = "Field: a\nField: b\n";
        let p = parse_all(input);
        assert_eq!(p[0].get("Field"), Some("a"));
        let vals: Vec<_> = p[0].iter().map(|(_, v)| v).collect();
        assert_eq!(vals, vec!["a", "b"]);
    }

    #[test]
    fn line_exceeding_ceiling_rejected() {
        let payload_len = 2 * 1024 * 1024;
        if MAX_LINE_BYTES <= payload_len {
            let s = format!("Field: {}", "a".repeat(payload_len));
            let err = Deb822Reader::new(Cursor::new(s))
                .read_paragraph()
                .unwrap_err();
            assert!(matches!(err, ParseError::LineTooLong { .. }), "{err:?}");
        } else {
            let s = format!("Field: {}", "a".repeat(MAX_LINE_BYTES));
            let err = Deb822Reader::new(Cursor::new(s))
                .read_paragraph()
                .unwrap_err();
            assert!(matches!(err, ParseError::LineTooLong { .. }), "{err:?}");
        }
    }

    #[test]
    fn line_exactly_at_ceiling_ok_when_bounded() {
        let short = "Field: value\n";
        Deb822Reader::new(Cursor::new(short))
            .read_paragraph()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn non_utf8_bytes_rejected() {
        let bytes: Vec<u8> = b"Field: value\xFFmore\n".to_vec();
        let err = Deb822Reader::new(Cursor::new(bytes))
            .read_paragraph()
            .unwrap_err();
        assert!(matches!(err, ParseError::InvalidUtf8 { .. }), "{err:?}");
    }

    #[test]
    fn utf8_multibyte_accepted() {
        let bytes: Vec<u8> = "Description: café — résumé\n".as_bytes().to_vec();
        let p = Deb822Reader::new(Cursor::new(bytes))
            .read_paragraph()
            .unwrap()
            .unwrap();
        assert_eq!(p.get("Description"), Some("café — résumé"));
    }

    #[test]
    fn paragraph_start_line_reflects_source_position() {
        let input = "\n\nPackage: a\n\nPackage: b\n";
        let mut r = Deb822Reader::new(Cursor::new(input));
        let a = r.read_paragraph().unwrap().unwrap();
        let b = r.read_paragraph().unwrap().unwrap();
        assert_eq!(a.start_line(), 3);
        assert_eq!(b.start_line(), 5);
    }

    #[test]
    fn paragraph_contains_and_len_and_empty() {
        let p = Paragraph::from_pairs(vec![("A", "1"), ("B", "2")]);
        assert_eq!(p.len(), 2);
        assert!(!p.is_empty());
        assert!(p.contains("a"));
        assert!(p.contains("B"));
        assert!(!p.contains("C"));
    }
}
