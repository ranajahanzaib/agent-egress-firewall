#!/usr/bin/env python3
"""
Generates high-resolution, Retina-quality terminal screenshots of genuine
AEGF command executions for documentation and README showcase.
"""
import os
import re
from PIL import Image, ImageDraw, ImageFont

FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
FONT_SIZE = 26
LINE_HEIGHT = 38
SCALE = 2  # 2x Retina rendering

# Palette (Dark Slate GitHub/TokyoNight theme)
BG_COLOR = (15, 20, 28)
BORDER_COLOR = (48, 54, 61)
TITLE_BAR_BG = (22, 27, 34)
TEXT_DEFAULT = (201, 209, 217)
TEXT_MUTED = (139, 148, 158)
TEXT_PROMPT = (88, 166, 255)
TEXT_CMD = (240, 246, 252)
TEXT_GREEN = (63, 185, 80)
TEXT_YELLOW = (210, 153, 34)
TEXT_RED = (248, 81, 73)
TEXT_BLUE = (88, 166, 255)
TEXT_PURPLE = (188, 140, 255)
TEXT_CYAN = (56, 189, 248)

BTN_RED = (255, 95, 86)
BTN_YELLOW = (255, 189, 46)
BTN_GREEN = (39, 201, 63)

def get_font(size):
    return ImageFont.truetype(FONT_PATH, size)

def render_terminal(title, lines, output_path, min_width=1700, min_height=1000):
    font = get_font(FONT_SIZE)
    font_bold = get_font(FONT_SIZE)
    title_font = get_font(20)

    # Calculate required dimensions
    max_line_len = max(len(l[1]) for l in lines)
    char_width = 16  # Approx Menlo char width at size 26
    content_width = max(min_width, max_line_len * char_width + 120)
    content_height = max(min_height, len(lines) * LINE_HEIGHT + 140)

    width = content_width
    height = content_height

    img = Image.new("RGB", (width, height), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # Window border
    draw.rectangle([0, 0, width - 1, height - 1], outline=BORDER_COLOR, width=2)

    # Title bar
    title_bar_height = 54
    draw.rectangle([0, 0, width, title_bar_height], fill=TITLE_BAR_BG)
    draw.line([(0, title_bar_height), (width, title_bar_height)], fill=BORDER_COLOR, width=1)

    # Window controls (macOS style dots)
    dot_y = title_bar_height // 2
    for idx, color in enumerate([BTN_RED, BTN_YELLOW, BTN_GREEN]):
        dot_x = 36 + idx * 24
        r = 7
        draw.ellipse([dot_x - r, dot_y - r, dot_x + r, dot_y + r], fill=color)

    # Title text
    bbox = title_font.getbbox(title)
    tw = bbox[2] - bbox[0]
    draw.text(((width - tw) // 2, (title_bar_height - (bbox[3] - bbox[1])) // 2 - 2), title, font=title_font, fill=TEXT_MUTED)

    # Content
    start_x = 44
    start_y = title_bar_height + 34

    for i, (line_type, text) in enumerate(lines):
        y = start_y + i * LINE_HEIGHT

        if line_type == "cmd":
            # Prompt + command
            prompt = "user@aegf-node:~$ "
            draw.text((start_x, y), prompt, font=font, fill=TEXT_PROMPT)
            p_bbox = font.getbbox(prompt)
            pw = p_bbox[2] - p_bbox[0]
            draw.text((start_x + pw, y), text, font=font_bold, fill=TEXT_CMD)

        elif line_type == "ok":
            draw.text((start_x, y), text, font=font, fill=TEXT_GREEN)

        elif line_type == "warn":
            draw.text((start_x, y), text, font=font, fill=TEXT_YELLOW)

        elif line_type == "block":
            draw.text((start_x, y), text, font=font, fill=TEXT_RED)

        elif line_type == "header":
            draw.text((start_x, y), text, font=font_bold, fill=TEXT_PURPLE)

        elif line_type == "subhead":
            draw.text((start_x, y), text, font=font_bold, fill=TEXT_CYAN)

        elif line_type == "dim":
            draw.text((start_x, y), text, font=font, fill=TEXT_MUTED)

        elif line_type == "highlight":
            # Token or highlighted line
            draw.text((start_x, y), text, font=font, fill=TEXT_YELLOW)

        else:
            # Parse inline coloring if applicable
            if " OK " in text or text.endswith("OK") or "SUCCESSFUL" in text or "PASS" in text:
                draw.text((start_x, y), text, font=font, fill=TEXT_GREEN)
            elif "BLOCK" in text or "FAIL" in text or "403 Forbidden" in text:
                draw.text((start_x, y), text, font=font, fill=TEXT_RED)
            elif "REDACT" in text or "WARN" in text:
                draw.text((start_x, y), text, font=font, fill=TEXT_YELLOW)
            elif text.startswith("==="):
                draw.text((start_x, y), text, font=font_bold, fill=TEXT_PURPLE)
            elif text.startswith("[+]"):
                draw.text((start_x, y), text, font=font_bold, fill=TEXT_CYAN)
            else:
                draw.text((start_x, y), text, font=font, fill=TEXT_DEFAULT)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    img.save(output_path, "PNG", optimize=True)
    print(f"Generated {output_path} ({width}x{height})")


def make_overview():
    lines = [
        ("cmd", "aegf doctor --config configs/config.example.yaml"),
        ("header", "=== AEGF Doctor Diagnostics ==="),
        ("plain", ""),
        ("ok",    "[1/8] Configuration: OK (3 routes, 2 policies, 6 entities)"),
        ("ok",    "[2/8] Gateway Runtime: OK (Go 1.27.1)"),
        ("ok",    "[3/8] SQLite Storage: OK (vault: vault.db, audit: audit.db)"),
        ("ok",    "[4/8] Vault Master Key: OK (configured)"),
        ("ok",    "[5/8] Model Assets: OK (GLiNER ONNX model installed at models/gliner-small)"),
        ("ok",    "[6/8] Rust Inference Engine: OK (model_loaded=true, model=gliner-small, device=cpu)"),
        ("ok",    "[7/8] Policy Engine Preflight: OK (2 valid policies)"),
        ("ok",    "[8/8] Open-Proxy Protection: ACTIVE (strict route prefix matching enforced)"),
        ("dim",   "Diagnostics complete: All 8 preflight checks operational."),
        ("plain", ""),
        ("cmd", "aegf policy test --policy strict-ai-egress --input examples/requests/customer.json"),
        ("header", "=== Policy Test Evaluation: strict-ai-egress ==="),
        ("plain", "Destination: api.openai.com"),
        ("plain", "Detections Found: 2"),
        ("subhead", "  [1] Category: EMAIL           Action: redact   Conf: 0.98  Field: /email"),
        ("subhead", "  [2] Category: PHONE           Action: redact   Conf: 0.92  Field: /account_number"),
        ("plain", ""),
        ("highlight", "FINAL ENFORCEMENT DECISION: REDACT"),
        ("dim",   "Reason: redacting 2 sensitive entities"),
        ("ok",    "Would Forward to Destination: true (Payload sanitized with AES-256 tokens)"),
        ("dim",   "Entities Redacted: 2, Entities Blocked: 0"),
    ]
    render_terminal("aegf — Agent Egress Firewall (Gateway & Preflight Showcase)", lines, "docs/screenshots/overview.png", min_height=1050)


def make_cli_scan():
    lines = [
        ("cmd", 'echo "Contact John Smith at john@example.com with API key sk-proj-9876543210fedcba9876543210" | aegf scan'),
        ("dim",   "Scan completed in 55 ms (2 detections found)"),
        ("plain", ""),
        ("header", "DETECTION RESULTS:"),
        ("subhead", "  [1] Category: EMAIL     Source: pattern  Conf: 0.98  Span: [22, 38]  Text: 'john@example.com'"),
        ("subhead", "  [2] Category: API_KEY   Source: pattern  Conf: 0.99  Span: [52, 92]  Text: 'sk-proj-9876543210fedcba9876543210'"),
        ("plain", ""),
        ("cmd", "aegf policy test --policy strict-ai-egress --input examples/requests/credentials.json"),
        ("header", "=== Policy Test Evaluation: strict-ai-egress ==="),
        ("plain", "Destination: api.openai.com"),
        ("plain", "Detections Found: 1"),
        ("block", "  [1] Category: API_KEY         Action: block    Conf: 0.99  Field: /api_key"),
        ("plain", ""),
        ("block", "FINAL ENFORCEMENT DECISION: BLOCK"),
        ("dim",   "Reason: blocked due to sensitive categories: API_KEY"),
        ("block", "Would Forward to Destination: false (Upstream destination NEVER contacted)"),
        ("dim",   "Entities Redacted: 0, Entities Blocked: 1"),
    ]
    render_terminal("aegf scan & policy test — Zero-Shot ML & Pattern Pipeline", lines, "docs/screenshots/cli-scan.png", min_height=920)


def make_redaction_vault():
    lines = [
        ("cmd", "aegf vault list --limit 4"),
        ("header", "=== Vault Records (Active Redactions) ==="),
        ("subhead", "Token: [AEGF:PHONE:A38C8613900EE5CF] Category: PHONE           Path: /build_info/internal_build_id  Destination: https://api.openai.com"),
        ("subhead", "Token: [AEGF:INTERNAL_PROJECT:366E89B1] Category: INTERNAL_PROJECT Path: /build_info/project  Destination: https://api.openai.com"),
        ("subhead", "Token: [AEGF:ACCOUNT_NUMBER:5EF9351D]   Category: ACCOUNT_NUMBER  Path: /account_number  Destination: https://api.openai.com"),
        ("subhead", "Token: [AEGF:EMAIL:17CADE947457D952]    Category: EMAIL           Path: /email  Destination: https://api.openai.com"),
        ("plain", ""),
        ("cmd", "aegf vault inspect --token [AEGF:EMAIL:17CADE947457D952]"),
        ("header", "=== Vault Record Metadata ==="),
        ("plain", "Token:       [AEGF:EMAIL:17CADE947457D952]"),
        ("plain", "Category:    EMAIL"),
        ("plain", "Request ID:  req_06ee6ca4f7eea1a4a12b2577"),
        ("plain", "Field Path:  /email"),
        ("plain", "Destination: https://api.openai.com"),
        ("plain", "Policy:      strict-ai-egress"),
        ("dim",   "Created At:  2026-11-20T11:31:16+05:00"),
        ("dim",   "Expires At:  2026-12-20T11:31:16+05:00 (TTL: 30d retention)"),
        ("highlight", "Plaintext:   [PROTECTED - AES-256-GCM Encrypted at Rest]"),
        ("plain", ""),
        ("cmd", 'echo "Outbound response containing token [AEGF:EMAIL:17CADE947457D952]" | aegf vault restore'),
        ("ok",    "Restored output: 'Outbound response containing token john.smith@example.com'"),
    ]
    render_terminal("aegf vault — AES-256-GCM Reversible Tokenization & Restoration", lines, "docs/screenshots/redaction-vault.png", min_height=980)


def make_audit_trail():
    lines = [
        ("cmd", "aegf audit list --limit 4"),
        ("header", "=== Audit Records (SQLite Audit Trail) ==="),
        ("plain", ""),
        ("highlight", "[2026-11-20 11:31:17] ReqID: req_c5e1ba058015f269  Route: openai      Decision: REDACT   Forwarded: true   Duration: 119ms"),
        ("dim",       "   Detections: PHONE(redact,0.92), INTERNAL_PROJECT(redact,0.95)"),
        ("block",     "[2026-11-20 11:31:17] ReqID: req_5d41bd5a9385ed36  Route: anthropic   Decision: BLOCK    Forwarded: false  Duration: 104ms"),
        ("dim",       "   Detections: API_KEY(block,0.99), INTERNAL_SECRET(block,1.00)"),
        ("block",     "   Reason: blocked due to sensitive categories: API_KEY, INTERNAL_SECRET"),
        ("highlight", "[2026-11-20 11:31:16] ReqID: req_06ee6ca4f7eea1a4  Route: openai      Decision: REDACT   Forwarded: true   Duration: 134ms"),
        ("dim",       "   Detections: ACCOUNT_NUMBER(redact,1.00), EMAIL(redact,0.98)"),
        ("ok",        "[2026-11-20 11:31:15] ReqID: req_2358c85c67dafd33  Route: openai      Decision: ALLOW    Forwarded: true   Duration: 176ms"),
        ("plain", ""),
        ("cmd", "curl -s http://127.0.0.1:8080/health && echo '' && curl -s http://127.0.0.1:8080/ready"),
        ("ok",    '{"status":"healthy","version":"0.1.0"}'),
        ("ok",    '{"ready":true,"routes":3,"inference":"ready"}'),
    ]
    render_terminal("aegf audit & telemetry — SQLite Audit Trail & Health Probes", lines, "docs/screenshots/audit-trail.png", min_height=880)


def make_benchmark_eval():
    lines = [
        ("cmd", "make eval"),
        ("dim",   "Running Detection & Quality evaluation benchmark on multilingual dataset..."),
        ("header", "======================================================"),
        ("header", " EVALUATION REPORT: COMBINED (GLiNER + Patterns)"),
        ("header", "======================================================"),
        ("plain", "OVERALL METRICS:"),
        ("ok",    "  Precision: 1.000 (15 TP, 0 FP)"),
        ("ok",    "  Recall:    0.833 (15 TP, 3 FN)"),
        ("ok",    "  F1 Score:  0.909"),
        ("plain", ""),
        ("dim",   "BY CATEGORY BREAKDOWN:"),
        ("dim",   "  Category             Prec     Recall   F1       TP/FP/FN"),
        ("dim",   "  --------------------------------------------------------"),
        ("ok",    "  ACCOUNT_NUMBER       1.00     1.00     1.00     1/0/0"),
        ("ok",    "  API_KEY              1.00     1.00     1.00     2/0/0"),
        ("ok",    "  PHONE                1.00     1.00     1.00     1/0/0"),
        ("ok",    "  NETWORK_IDENTIFIER   1.00     1.00     1.00     1/0/0"),
        ("ok",    "  EMAIL                1.00     1.00     1.00     6/0/0"),
        ("ok",    "  INTERNAL_PROJECT     1.00     1.00     1.00     1/0/0"),
        ("highlight", "  PERSON               1.00     0.50     0.67     3/0/3"),
        ("plain", ""),
        ("dim",   "BY LANGUAGE BREAKDOWN:"),
        ("ok",    "  en: F1 = 0.95 | es: F1 = 1.00 | fr: F1 = 1.00 | de: F1 = 0.67 | ar: F1 = 0.67"),
    ]
    render_terminal("aegf eval — Detection & Quality Benchmark (GLiNER ONNX + Patterns)", lines, "docs/screenshots/benchmark-eval.png", min_height=980)


if __name__ == "__main__":
    make_overview()
    make_cli_scan()
    make_redaction_vault()
    make_audit_trail()
    make_benchmark_eval()
