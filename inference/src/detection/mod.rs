use crate::gliner::GlinerEngine;
use crate::patterns::{CompiledPattern, PatternDetector};
use crate::spans::{Span, resolve_overlapping_spans};
use std::sync::Arc;

pub struct DetectionEngine {
    gliner: Option<Arc<GlinerEngine>>,
}

impl DetectionEngine {
    pub fn new(gliner: Option<Arc<GlinerEngine>>) -> Self {
        Self { gliner }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn scan_field(
        &self,
        field_id: &str,
        text: &str,
        labels: &[String],
        custom_patterns: &[CompiledPattern],
        min_confidence: f64,
        enable_ml: bool,
        enable_patterns: bool,
    ) -> Vec<Span> {
        let mut raw_spans = Vec::new();

        // 1. Run deterministic patterns if enabled
        if enable_patterns {
            let mut detector = PatternDetector::new();
            for cp in custom_patterns {
                detector.add_pattern(CompiledPattern {
                    name: cp.name.clone(),
                    category: cp.category.clone(),
                    regex: cp.regex.clone(),
                    confidence: cp.confidence,
                });
            }
            let pattern_spans = detector.scan_field(field_id, text);
            for s in pattern_spans {
                if s.confidence >= min_confidence {
                    raw_spans.push(s);
                }
            }
        }

        // 2. Run GLiNER if enabled and engine is available
        #[allow(clippy::collapsible_if)]
        if enable_ml {
            if let Some(engine) = &self.gliner {
                match engine.predict(field_id, text, labels, min_confidence) {
                    Ok(ml_spans) => {
                        raw_spans.extend(ml_spans);
                    }
                    Err(e) => {
                        tracing::warn!("GLiNER prediction error on field {}: {}", field_id, e);
                    }
                }
            }
        }

        // 3. Resolve overlapping detections deterministically
        resolve_overlapping_spans(raw_spans)
    }
}
