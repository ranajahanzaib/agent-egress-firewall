use crate::spans::{Span, byte_to_char_offset};
use regex::Regex;
use std::sync::LazyLock;

pub struct CompiledPattern {
    pub name: String,
    pub category: String,
    pub regex: Regex,
    pub confidence: f64,
}

// Built-in pattern definitions
static EMAIL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").unwrap());

static PHONE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // E.164 and common national phone formats
    Regex::new(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b").unwrap()
});

static IPV4_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static IPV6_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}\b|\b(?:[a-f0-9]{1,4}:)*:[a-f0-9]{1,4}\b")
        .unwrap()
});

static CREDIT_CARD_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b").unwrap());

static OPENAI_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-[a-zA-Z0-9_-]{20,}\b").unwrap());

static ANTHROPIC_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b").unwrap());

static GITHUB_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b").unwrap());

static AWS_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").unwrap());

static SLACK_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bxox[baprs]-[0-9a-zA-Z-]{10,}\b").unwrap());

static JWT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b").unwrap()
});

static PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----").unwrap()
});

/// Validates a credit card number using the Luhn algorithm.
pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0;
    let mut double = false;

    for &digit in digits.iter().rev() {
        if double {
            let doubled = digit * 2;
            sum += if doubled > 9 { doubled - 9 } else { doubled };
        } else {
            sum += digit;
        }
        double = !double;
    }

    sum % 10 == 0
}

pub struct PatternDetector {
    custom_patterns: Vec<CompiledPattern>,
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternDetector {
    pub fn new() -> Self {
        Self {
            custom_patterns: Vec::new(),
        }
    }

    pub fn with_custom_patterns(patterns: Vec<CompiledPattern>) -> Self {
        Self {
            custom_patterns: patterns,
        }
    }

    pub fn add_pattern(&mut self, pattern: CompiledPattern) {
        self.custom_patterns.push(pattern);
    }

    pub fn scan_field(&self, field_id: &str, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();

        // 1. Private keys (high confidence 1.0)
        for m in PRIVATE_KEY_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "PRIVATE_KEY".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 1.0,
                source: "pattern".to_string(),
                detector_id: "private_key_pem".to_string(),
                label: "PRIVATE_KEY".to_string(),
            });
        }

        // 2. API Keys
        for m in OPENAI_KEY_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "API_KEY".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.99,
                source: "pattern".to_string(),
                detector_id: "openai_key".to_string(),
                label: "API_KEY".to_string(),
            });
        }

        for m in ANTHROPIC_KEY_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "API_KEY".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.99,
                source: "pattern".to_string(),
                detector_id: "anthropic_key".to_string(),
                label: "API_KEY".to_string(),
            });
        }

        for m in GITHUB_TOKEN_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "API_KEY".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.99,
                source: "pattern".to_string(),
                detector_id: "github_token".to_string(),
                label: "API_KEY".to_string(),
            });
        }

        for m in AWS_KEY_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "API_KEY".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.99,
                source: "pattern".to_string(),
                detector_id: "aws_access_key".to_string(),
                label: "API_KEY".to_string(),
            });
        }

        for m in SLACK_TOKEN_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "API_KEY".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.99,
                source: "pattern".to_string(),
                detector_id: "slack_token".to_string(),
                label: "API_KEY".to_string(),
            });
        }

        // 3. JWT Tokens
        for m in JWT_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "INTERNAL_SECRET".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.98,
                source: "pattern".to_string(),
                detector_id: "jwt_token".to_string(),
                label: "INTERNAL_SECRET".to_string(),
            });
        }

        // 4. Email addresses
        for m in EMAIL_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "EMAIL".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.98,
                source: "pattern".to_string(),
                detector_id: "email_regex".to_string(),
                label: "EMAIL".to_string(),
            });
        }

        // 5. Phone numbers
        for m in PHONE_REGEX.find_iter(text) {
            let match_str = m.as_str();
            // Validate minimum digit count
            let digit_count = match_str.chars().filter(|c| c.is_ascii_digit()).count();
            if (7..=15).contains(&digit_count) {
                let start = byte_to_char_offset(text, m.start());
                let end = byte_to_char_offset(text, m.end());
                spans.push(Span {
                    field_id: field_id.to_string(),
                    category: "PHONE".to_string(),
                    start,
                    end,
                    text: match_str.to_string(),
                    confidence: 0.92,
                    source: "pattern".to_string(),
                    detector_id: "phone_regex".to_string(),
                    label: "PHONE".to_string(),
                });
            }
        }

        // 6. Credit Card Numbers (with Luhn check)
        for m in CREDIT_CARD_REGEX.find_iter(text) {
            let match_str = m.as_str();
            if luhn_check(match_str) {
                let start = byte_to_char_offset(text, m.start());
                let end = byte_to_char_offset(text, m.end());
                spans.push(Span {
                    field_id: field_id.to_string(),
                    category: "ACCOUNT_NUMBER".to_string(),
                    start,
                    end,
                    text: match_str.to_string(),
                    confidence: 0.99,
                    source: "pattern".to_string(),
                    detector_id: "credit_card_luhn".to_string(),
                    label: "ACCOUNT_NUMBER".to_string(),
                });
            }
        }

        // 7. IP addresses
        for m in IPV4_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "NETWORK_IDENTIFIER".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.90,
                source: "pattern".to_string(),
                detector_id: "ipv4_regex".to_string(),
                label: "NETWORK_IDENTIFIER".to_string(),
            });
        }

        for m in IPV6_REGEX.find_iter(text) {
            let start = byte_to_char_offset(text, m.start());
            let end = byte_to_char_offset(text, m.end());
            spans.push(Span {
                field_id: field_id.to_string(),
                category: "NETWORK_IDENTIFIER".to_string(),
                start,
                end,
                text: m.as_str().to_string(),
                confidence: 0.90,
                source: "pattern".to_string(),
                detector_id: "ipv6_regex".to_string(),
                label: "NETWORK_IDENTIFIER".to_string(),
            });
        }

        // 8. Custom user-configured patterns
        for custom in &self.custom_patterns {
            for m in custom.regex.find_iter(text) {
                let start = byte_to_char_offset(text, m.start());
                let end = byte_to_char_offset(text, m.end());
                spans.push(Span {
                    field_id: field_id.to_string(),
                    category: custom.category.clone(),
                    start,
                    end,
                    text: m.as_str().to_string(),
                    confidence: custom.confidence,
                    source: "pattern".to_string(),
                    detector_id: custom.name.clone(),
                    label: custom.category.clone(),
                });
            }
        }

        crate::spans::resolve_overlapping_spans(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let detector = PatternDetector::new();
        let spans = detector.scan_field("body", "Please email alice.smith@example.org for info");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].category, "EMAIL");
        assert_eq!(spans[0].text, "alice.smith@example.org");
    }

    #[test]
    fn test_api_key_detection() {
        let detector = PatternDetector::new();
        let spans = detector.scan_field("auth", "sk-proj-1234567890abcdef1234567890");
        println!("Spans found: {:?}", spans);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].category, "API_KEY");
    }

    #[test]
    fn test_luhn_credit_card() {
        // Valid Visa test number
        assert!(luhn_check("4532-0150-1234-5671"));
        // Invalid number
        assert!(!luhn_check("4532-0150-1234-5675"));
    }
}
