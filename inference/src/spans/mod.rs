use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    pub field_id: String,
    pub category: String,
    pub start: usize, // Unicode character offset (0-indexed)
    pub end: usize,   // Unicode character offset (exclusive)
    pub text: String,
    pub confidence: f64,
    pub source: String,
    pub detector_id: String,
    pub label: String,
}

impl Span {
    pub fn overlaps_with(&self, other: &Span) -> bool {
        if self.field_id != other.field_id {
            return false;
        }
        self.start < other.end && other.start < self.end
    }
}

/// Convert byte offsets in UTF-8 string to Unicode character offsets
pub fn byte_to_char_offset(text: &str, byte_offset: usize) -> usize {
    let bounded = byte_offset.min(text.len());
    // Count chars up to bounded byte offset
    text[..bounded].chars().count()
}

/// Convert Unicode character offsets to byte offsets in UTF-8 string
pub fn char_to_byte_offset(text: &str, char_offset: usize) -> usize {
    text.char_indices()
        .nth(char_offset)
        .map(|(idx, _)| idx)
        .unwrap_or(text.len())
}

/// Resolves conflicting/overlapping spans deterministically.
/// Rules:
/// 1. Higher confidence wins.
/// 2. If confidence is equal, deterministic patterns win over ML (more specific format guarantee).
/// 3. If source is equal, longer span wins.
/// 4. If length is equal, earlier start offset wins.
pub fn resolve_overlapping_spans(mut spans: Vec<Span>) -> Vec<Span> {
    if spans.is_empty() {
        return spans;
    }

    // Sort by priority descending
    spans.sort_by(|a, b| {
        // Priority 1: confidence (descending)
        let conf_cmp = b
            .confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(Ordering::Equal);
        if conf_cmp != Ordering::Equal {
            return conf_cmp;
        }

        // Priority 2: pattern detector beats ml
        let a_is_pattern = a.source == "pattern";
        let b_is_pattern = b.source == "pattern";
        if a_is_pattern != b_is_pattern {
            return b_is_pattern.cmp(&a_is_pattern);
        }

        // Priority 3: length (longer wins)
        let a_len = a.end.saturating_sub(a.start);
        let b_len = b.end.saturating_sub(b.start);
        if a_len != b_len {
            return b_len.cmp(&a_len);
        }

        // Priority 4: earlier start offset
        a.start.cmp(&b.start)
    });

    let mut accepted: Vec<Span> = Vec::new();
    for span in spans {
        let has_conflict = accepted.iter().any(|acc| acc.overlaps_with(&span));
        if !has_conflict {
            accepted.push(span);
        }
    }

    // Sort accepted spans by field_id then start offset for predictable output
    accepted.sort_by(|a, b| {
        let field_cmp = a.field_id.cmp(&b.field_id);
        if field_cmp != Ordering::Equal {
            field_cmp
        } else {
            a.start.cmp(&b.start)
        }
    });

    accepted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unicode_offset_conversion() {
        let text = "Hello 👋 world! 🌍 مرحبا";
        let byte_len = text.len();
        let char_len = text.chars().count();
        assert_ne!(byte_len, char_len);

        let char_idx = 7; // after 👋 and space
        let byte_idx = char_to_byte_offset(text, char_idx);
        let back_char = byte_to_char_offset(text, byte_idx);
        assert_eq!(char_idx, back_char);
    }

    #[test]
    fn test_resolve_overlapping_spans() {
        let span1 = Span {
            field_id: "f1".into(),
            category: "PERSON".into(),
            start: 0,
            end: 10,
            text: "John Smith".into(),
            confidence: 0.85,
            source: "gliner".into(),
            detector_id: "gliner-small".into(),
            label: "person".into(),
        };

        let span2 = Span {
            field_id: "f1".into(),
            category: "EMAIL".into(),
            start: 5,
            end: 25,
            text: "Smith@example.com".into(),
            confidence: 0.99,
            source: "pattern".into(),
            detector_id: "email_regex".into(),
            label: "EMAIL".into(),
        };

        let resolved = resolve_overlapping_spans(vec![span1, span2.clone()]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].category, "EMAIL");
        assert_eq!(resolved[0].confidence, 0.99);
    }
}
