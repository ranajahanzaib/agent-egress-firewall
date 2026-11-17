pub mod config;
pub mod detection;
pub mod gliner;
pub mod grpc;
pub mod patterns;
pub mod spans;

use clap::Parser;
use config::Config;
use detection::DetectionEngine;
use gliner::GlinerEngine;
use grpc::InferenceServiceImpl;
use grpc::proto::inference_service_server::InferenceServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::parse();
    tracing::info!("Starting AEGF Inference Engine on {}", config.listen);

    let (gliner_opt, model_name, model_path, model_loaded, default_labels) = if !config.disable_ml
        && config.model_dir.exists()
    {
        tracing::info!("Loading GLiNER ONNX model from {:?}", config.model_dir);
        match GlinerEngine::load(&config.model_dir) {
            Ok(engine) => {
                let name = engine.model_name.clone();
                let path = engine.model_path.clone();
                let labels = engine.default_labels.clone();
                tracing::info!("Successfully loaded model '{}'", name);
                (Some(Arc::new(engine)), name, path, true, labels)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load GLiNER model: {}. Running in deterministic-only mode.",
                    e
                );
                (
                    None,
                    "none".into(),
                    config.model_dir.to_string_lossy().to_string(),
                    false,
                    vec!["person".into(), "email".into(), "phone".into()],
                )
            }
        }
    } else {
        tracing::info!(
            "ML inference disabled or model directory not found. Running deterministic-only mode."
        );
        (
            None,
            "none".into(),
            String::new(),
            false,
            vec!["person".into(), "email".into(), "phone".into()],
        )
    };

    let detection_engine = Arc::new(DetectionEngine::new(gliner_opt));
    let service_impl = InferenceServiceImpl::new(
        detection_engine,
        model_name,
        model_path,
        model_loaded,
        default_labels,
    );

    let addr: SocketAddr = config.listen.parse()?;
    tracing::info!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(InferenceServiceServer::new(service_impl))
        .serve(addr)
        .await?;

    Ok(())
}
