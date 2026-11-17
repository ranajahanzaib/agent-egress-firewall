pub mod proto {
    tonic::include_proto!("inference.v1");
}

use self::proto::inference_service_server::InferenceService;
use self::proto::{
    Detection as ProtoDetection, HealthRequest, HealthResponse, ModelStatusRequest,
    ModelStatusResponse, ScanRequest, ScanResponse, ServingStatus,
};
use crate::detection::DetectionEngine;
use crate::patterns::CompiledPattern;
use regex::Regex;
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};

pub struct InferenceServiceImpl {
    engine: Arc<DetectionEngine>,
    model_name: String,
    model_path: String,
    model_loaded: bool,
    default_labels: Vec<String>,
}

impl InferenceServiceImpl {
    pub fn new(
        engine: Arc<DetectionEngine>,
        model_name: String,
        model_path: String,
        model_loaded: bool,
        default_labels: Vec<String>,
    ) -> Self {
        Self {
            engine,
            model_name,
            model_path,
            model_loaded,
            default_labels,
        }
    }
}

#[tonic::async_trait]
impl InferenceService for InferenceServiceImpl {
    async fn scan(&self, request: Request<ScanRequest>) -> Result<Response<ScanResponse>, Status> {
        let t0 = Instant::now();
        let req = request.into_inner();

        let options = req.options.unwrap_or_default();
        let enable_ml = options.enable_ml;
        let enable_patterns = options.enable_patterns;
        let min_confidence = if options.default_min_confidence > 0.0 {
            options.default_min_confidence
        } else {
            0.50
        };

        // Determine dynamic labels to search for
        let mut labels = Vec::new();
        if !req.entities.is_empty() {
            for ent in req.entities {
                if ent.enabled && !ent.name.trim().is_empty() {
                    labels.push(ent.name);
                }
            }
        }
        if labels.is_empty() {
            labels = self.default_labels.clone();
        }

        // Parse custom regex patterns safely
        let mut custom_patterns = Vec::new();
        for p in req.patterns {
            if !p.enabled || p.regex.trim().is_empty() {
                continue;
            }
            // Enforce maximum pattern length to avoid malicious regex patterns
            if p.regex.len() > 500 {
                return Err(Status::invalid_argument(format!(
                    "Pattern '{}' exceeds maximum allowed regex length (500 chars)",
                    p.name
                )));
            }
            match Regex::new(&p.regex) {
                Ok(r) => {
                    let conf = if p.confidence > 0.0 {
                        p.confidence
                    } else {
                        1.0
                    };
                    custom_patterns.push(CompiledPattern {
                        name: p.name,
                        category: p.category,
                        regex: r,
                        confidence: conf,
                    });
                }
                Err(e) => {
                    return Err(Status::invalid_argument(format!(
                        "Invalid regex pattern for '{}': {}",
                        p.name, e
                    )));
                }
            }
        }

        let mut all_detections = Vec::new();

        for field in req.fields {
            let spans = self.engine.scan_field(
                &field.field_id,
                &field.text,
                &labels,
                &custom_patterns,
                min_confidence,
                enable_ml,
                enable_patterns,
            );

            for span in spans {
                all_detections.push(ProtoDetection {
                    field_id: span.field_id,
                    category: span.category,
                    start: span.start as u32,
                    end: span.end as u32,
                    text: span.text,
                    confidence: span.confidence,
                    source: span.source,
                    detector_id: span.detector_id,
                    label: span.label,
                });
            }
        }

        let duration_ms = t0.elapsed().as_millis() as u64;

        Ok(Response::new(ScanResponse {
            request_id: req.request_id,
            detections: all_detections,
            model_id: self.model_name.clone(),
            inference_duration_ms: duration_ms,
            success: true,
            error_message: String::new(),
        }))
    }

    async fn check_health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServingStatus::Serving as i32,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    async fn get_model_status(
        &self,
        _request: Request<ModelStatusRequest>,
    ) -> Result<Response<ModelStatusResponse>, Status> {
        Ok(Response::new(ModelStatusResponse {
            model_loaded: self.model_loaded,
            model_name: self.model_name.clone(),
            model_path: self.model_path.clone(),
            device: "cpu".to_string(),
            max_sequence_length: 512,
            default_entities: self.default_labels.clone(),
        }))
    }
}
