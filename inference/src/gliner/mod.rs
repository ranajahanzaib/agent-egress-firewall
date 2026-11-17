use crate::spans::{Span, byte_to_char_offset};
use ndarray::{Array2, Array3};
use ort::session::Session;
use ort::value::Value;
use regex::Regex;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokenizers::Tokenizer;

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[derive(Debug, Clone)]
pub struct WordToken {
    pub word: String,
    pub char_start: usize,
    pub char_end: usize,
}

pub struct GlinerEngine {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    pub model_name: String,
    pub model_path: String,
    pub max_width: usize,
    pub default_labels: Vec<String>,
}

impl GlinerEngine {
    pub fn load<P: AsRef<Path>>(model_dir: P) -> anyhow::Result<Self> {
        let dir = model_dir.as_ref();
        let onnx_path = if dir.join("model_quantized.onnx").exists() {
            dir.join("model_quantized.onnx")
        } else if dir.join("model.onnx").exists() {
            dir.join("model.onnx")
        } else {
            return Err(anyhow::anyhow!("No ONNX model found in {:?}", dir));
        };

        let tok_path = dir.join("tokenizer.json");
        if !tok_path.exists() {
            return Err(anyhow::anyhow!("No tokenizer.json found in {:?}", dir));
        }

        let env = Arc::new(ort::init().with_name("gliner").build()?);
        let session = Session::builder(&env)?.commit_from_file(&onnx_path)?;
        let tokenizer = Tokenizer::from_file(&tok_path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;

        let model_name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("gliner")
            .to_string();

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            model_name,
            model_path: onnx_path.to_string_lossy().to_string(),
            max_width: 12,
            default_labels: vec![
                "person".into(),
                "email".into(),
                "phone number".into(),
                "address".into(),
                "organization".into(),
                "account number".into(),
            ],
        })
    }

    /// Split text into word tokens preserving character start and end offsets.
    pub fn segment_words(text: &str) -> Vec<WordToken> {
        let re = Regex::new(r"\S+").unwrap();
        let mut words = Vec::new();

        for m in re.find_iter(text) {
            let start_char = byte_to_char_offset(text, m.start());
            let end_char = byte_to_char_offset(text, m.end());
            words.push(WordToken {
                word: m.as_str().to_string(),
                char_start: start_char,
                char_end: end_char,
            });
        }
        words
    }

    pub fn predict(
        &self,
        field_id: &str,
        text: &str,
        labels: &[String],
        threshold: f64,
    ) -> anyhow::Result<Vec<Span>> {
        if text.trim().is_empty() || labels.is_empty() {
            return Ok(Vec::new());
        }

        let words = Self::segment_words(text);
        let num_words = words.len();
        if num_words == 0 {
            return Ok(Vec::new());
        }

        // Build label prompt prefix: <<ENT>> label0 <<ENT>> label1 ... <<SEP>>
        let mut prompt = String::new();
        for l in labels {
            prompt.push_str("<<ENT>> ");
            prompt.push_str(l.to_lowercase().as_str());
            prompt.push(' ');
        }
        prompt.push_str("<<SEP>> ");

        let prompt_encoding = self
            .tokenizer
            .encode(prompt.as_str(), false)
            .map_err(|e| anyhow::anyhow!("Tokenization error: {}", e))?;
        let prompt_ids: Vec<i64> = prompt_encoding
            .get_ids()
            .iter()
            .map(|&id| id as i64)
            .collect();

        let mut input_ids = prompt_ids.clone();
        let mut words_mask: Vec<i64> = vec![0; prompt_ids.len()];

        for (w_idx, w) in words.iter().enumerate() {
            let word_enc = self
                .tokenizer
                .encode(format!(" {}", w.word), false)
                .map_err(|e| anyhow::anyhow!("Tokenization error: {}", e))?;
            let ids = word_enc.get_ids();
            for (sub_i, &id) in ids.iter().enumerate() {
                input_ids.push(id as i64);
                if sub_i == 0 {
                    words_mask.push((w_idx + 1) as i64);
                } else {
                    words_mask.push(0);
                }
            }
        }

        let seq_len = input_ids.len();
        let attention_mask = vec![1i64; seq_len];
        let text_lengths = vec![num_words as i64];

        // Generate candidate spans
        let mut span_idx_vec: Vec<[i64; 2]> = Vec::new();
        let mut span_mask: Vec<bool> = Vec::new();
        for start in 0..num_words {
            for k in 0..self.max_width {
                let end = (start + k).min(num_words - 1);
                span_idx_vec.push([start as i64, end as i64]);
                span_mask.push(start + k < num_words);
            }
        }
        let num_spans = span_idx_vec.len();

        let input_ids_arr = Array2::from_shape_vec((1, seq_len), input_ids)?;
        let attention_mask_arr = Array2::from_shape_vec((1, seq_len), attention_mask)?;
        let words_mask_arr = Array2::from_shape_vec((1, seq_len), words_mask)?;
        let text_lengths_arr = Array2::from_shape_vec((1, 1), text_lengths)?;

        let mut span_idx_flat = Vec::with_capacity(num_spans * 2);
        for s in &span_idx_vec {
            span_idx_flat.push(s[0]);
            span_idx_flat.push(s[1]);
        }
        let span_idx_arr = Array3::from_shape_vec((1, num_spans, 2), span_idx_flat)?;
        let span_mask_arr = Array2::from_shape_vec((1, num_spans), span_mask)?;

        let inputs = ort::inputs![
            "input_ids" => Value::from_array(input_ids_arr)?,
            "attention_mask" => Value::from_array(attention_mask_arr)?,
            "words_mask" => Value::from_array(words_mask_arr)?,
            "text_lengths" => Value::from_array(text_lengths_arr)?,
            "span_idx" => Value::from_array(span_idx_arr)?,
            "span_mask" => Value::from_array(span_mask_arr)?,
        ];

        let mut session = self
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("Inference session mutex poisoned"))?;
        let outputs = session.run(inputs)?;
        let (shape, data) = outputs["logits"].try_extract_tensor::<f32>()?;

        // Shape: [batch=1, num_words, max_width, num_classes]
        let dims: Vec<usize> = shape.iter().map(|&d| d as usize).collect();
        if dims.len() < 4 {
            return Err(anyhow::anyhow!("Unexpected logits shape: {:?}", shape));
        }
        let num_w = dims[1];
        let max_w = dims[2];
        let num_c = dims[3];

        let mut findings = Vec::new();
        let text_chars: Vec<char> = text.chars().collect();

        for w in 0..num_w {
            for k in 0..max_w {
                if w + k >= num_words {
                    continue;
                }
                for (c, label_str) in labels.iter().enumerate().take(num_c) {
                    let idx = w * (max_w * num_c) + k * num_c + c;
                    let logit = data[idx];
                    let prob = sigmoid(logit) as f64;

                    if prob >= threshold {
                        let start_char = words[w].char_start;
                        let end_char = words[w + k].char_end;
                        let span_text: String = text_chars[start_char..end_char].iter().collect();

                        let label_lower = label_str.to_lowercase();
                        let category = match label_lower.as_str() {
                            "person" => "PERSON",
                            "email" => "EMAIL",
                            "phone" | "phone number" => "PHONE",
                            "address" | "location" => "LOCATION",
                            "organization" | "company" => "ORGANIZATION",
                            "account number" => "ACCOUNT_NUMBER",
                            "medical identifier" => "MEDICAL_IDENTIFIER",
                            "internal project" => "INTERNAL_PROJECT",
                            _ => label_str.as_str(),
                        };

                        findings.push(Span {
                            field_id: field_id.to_string(),
                            category: category.to_uppercase(),
                            start: start_char,
                            end: end_char,
                            text: span_text,
                            confidence: (prob * 1000.0).round() / 1000.0,
                            source: "gliner".to_string(),
                            detector_id: self.model_name.clone(),
                            label: label_str.clone(),
                        });
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_segmentation() {
        let text = "Hello 👋 world! 🌍 John Smith";
        let words = GlinerEngine::segment_words(text);
        assert_eq!(words.len(), 6);
        assert_eq!(words[0].word, "Hello");
        assert_eq!(words[5].word, "Smith");
    }

    #[test]
    fn test_gliner_model_if_present() {
        let path = Path::new("../models/gliner-small");
        if !path.exists() {
            println!("Skipping model test: model dir does not exist");
            return;
        }

        let engine = GlinerEngine::load(path).expect("Failed to load gliner model");
        let labels = vec!["person".to_string(), "email".to_string()];
        let findings = engine
            .predict(
                "test_field",
                "Hello, my name is John Smith and my email is john@example.com",
                &labels,
                0.40,
            )
            .expect("Prediction failed");

        assert!(!findings.is_empty());
        let person_found = findings
            .iter()
            .any(|f| f.category == "PERSON" && f.text == "John Smith");
        assert!(
            person_found,
            "Expected to find PERSON John Smith, found: {:?}",
            findings
        );
    }
}
