use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "aegf-inference")]
#[command(about = "AEGF Rust Detection & Inference Engine", long_about = None)]
pub struct Config {
    #[arg(long, env = "AEGF_INFERENCE_LISTEN", default_value = "127.0.0.1:50051")]
    pub listen: String,

    #[arg(long, env = "AEGF_MODEL_DIR", default_value = "models/gliner-small")]
    pub model_dir: PathBuf,

    #[arg(long, env = "AEGF_DISABLE_ML", default_value_t = false)]
    pub disable_ml: bool,
}
