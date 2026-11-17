#!/usr/bin/env python3
"""
Downloads and installs GLiNER ONNX model weights and tokenizer configurations
locally into the models/ directory.
"""
import os
import sys
import urllib.request
import time

MODEL_REPO = "nexuswho/gliner-onnx-small"
FILES = [
    ("model_quantized.onnx", "https://huggingface.co/nexuswho/gliner-onnx-small/resolve/main/model_quantized.onnx"),
    ("tokenizer.json", "https://huggingface.co/nexuswho/gliner-onnx-small/raw/main/tokenizer.json"),
    ("tokenizer_config.json", "https://huggingface.co/nexuswho/gliner-onnx-small/raw/main/tokenizer_config.json"),
    ("gliner_config.json", "https://huggingface.co/nexuswho/gliner-onnx-small/raw/main/gliner_config.json"),
]

def reporthook(count, block_size, total_size):
    if total_size > 0 and count % 500 == 0:
        percent = int(count * block_size * 100 / total_size)
        mb_down = count * block_size // (1024 * 1024)
        mb_total = total_size // (1024 * 1024)
        sys.stdout.write(f"\r  [{percent}%] {mb_down}MB / {mb_total}MB")
        sys.stdout.flush()

def main():
    dest_dir = os.path.join(os.path.dirname(__file__), "..", "models", "gliner-small")
    os.makedirs(dest_dir, exist_ok=True)
    print(f"Downloading {MODEL_REPO} assets to {dest_dir}...")

    for fname, url in FILES:
        out_path = os.path.join(dest_dir, fname)
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            print(f"  [EXISTS] {fname} ({os.path.getsize(out_path)} bytes)")
            continue

        print(f"  Downloading {fname}...")
        t0 = time.time()
        urllib.request.urlretrieve(url, out_path, reporthook)
        print(f"\n  Done in {time.time() - t0:.1f}s ({os.path.getsize(out_path)} bytes)")

    print("Model installation complete.")

if __name__ == "__main__":
    main()
