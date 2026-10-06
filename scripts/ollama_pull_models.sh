#!/bin/sh
# Manual model pull (host or container). Prefer compose ollama-init on stack start.
set -e
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
export OLLAMA_HOST
MODELS="${OLLAMA_PULL_MODELS:-qwen2.5:14b,qwen2.5:7b,deepseek-r1:14b,llama3.1:8b,gemma4:12b,qwen3.5:9b,nomic-embed-text}"

echo "Pulling models via ${OLLAMA_HOST}: ${MODELS}"
OLD_IFS=$IFS
IFS=,
for model in $MODELS; do
  model=$(echo "$model" | tr -d ' ')
  [ -z "$model" ] && continue
  echo "Pulling $model..."
  curl -sf "$OLLAMA_HOST/api/pull" -d "{\"name\":\"$model\"}" || echo "Warning: failed to pull $model"
done
IFS=$OLD_IFS
echo "Model pull complete."
