#!/usr/bin/env bash
# Download the prompt-injection model artifacts the `prompt-injection` feature
# needs: the DeBERTa-v3 ONNX weights and its tokenizer.
#
# The weights are ~739 MB fp32 and are NOT vendored. This fetches them into a
# directory the PromptInjectionScanner loads. The feature-gated integration test
# (tests/prompt_injection.rs) reads CERBERUST_MODEL_DIR, defaulting to the path
# this script writes.
set -euo pipefail

REPO="protectai/deberta-v3-base-prompt-injection-v2"
DEST="${1:-${CERBERUST_MODEL_DIR:-$HOME/.cache/cerberust/deberta-v3-base-prompt-injection-v2}}"
BASE="https://huggingface.co/${REPO}/resolve/main"

mkdir -p "$DEST"

fetch() {
  local rel="$1" out="$2"
  if [[ -s "$out" ]]; then
    echo "have $(basename "$out") ($(du -h "$out" | cut -f1))"
    return
  fi
  echo "fetching $(basename "$out") ..."
  curl -fsSL -o "$out" "${BASE}/${rel}"
}

fetch "tokenizer.json" "${DEST}/tokenizer.json"
fetch "config.json" "${DEST}/config.json"
fetch "onnx/model.onnx" "${DEST}/model.onnx"

echo
echo "model ready in: ${DEST}"
echo "run the integration test with:"
echo "  CERBERUST_MODEL_DIR='${DEST}' cargo test --features prompt-injection --test prompt_injection -- --ignored"
