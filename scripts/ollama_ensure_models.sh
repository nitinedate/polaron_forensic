#!/bin/sh
# Pull required Ollama models for the detected GPU, then extra accuracy models
# that fit in VRAM. Runs as the ollama-init one-shot on compose up.
set -eu

export OLLAMA_HOST="${OLLAMA_HOST:-http://ollama:11434}"

probe_vram_mb() {
  if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null \
      | head -n 1 \
      | awk '{print int($1+0)}' || echo 0
  else
    echo 0
  fi
}

# Override: OLLAMA_PULL_MODELS=a,b  forces that list (still GPU-filtered unless
# OLLAMA_PULL_IGNORE_GPU=true). Accuracy extras still append when VRAM allows
# unless OLLAMA_PULL_ACCURACY=false.
VRAM_MB="$(probe_vram_mb)"
[ -z "$VRAM_MB" ] && VRAM_MB=0
IGNORE_GPU="${OLLAMA_PULL_IGNORE_GPU:-false}"
PULL_ACCURACY="${OLLAMA_PULL_ACCURACY:-true}"

echo "GPU probe: nvidia-smi VRAM=${VRAM_MB}MB ignore_gpu=${IGNORE_GPU}"

REQUIRED=""
ACCURACY=""
if [ "$IGNORE_GPU" = "true" ] && [ -n "${OLLAMA_PULL_MODELS:-}" ]; then
  REQUIRED="${OLLAMA_PULL_MODELS}"
else
  REQUIRED="nomic-embed-text,qwen2.5:7b"
  if [ "$VRAM_MB" -le 0 ]; then
    REQUIRED="${REQUIRED},llama3.1:8b"
    echo "No GPU VRAM — CPU-safe required models only."
  elif [ "$VRAM_MB" -lt 8000 ]; then
    REQUIRED="${REQUIRED},llama3.1:8b,qwen3.5:9b"
  elif [ "$VRAM_MB" -lt 10000 ]; then
    REQUIRED="${REQUIRED},llama3.1:8b,qwen3.5:9b"
  elif [ "$VRAM_MB" -lt 12000 ]; then
    REQUIRED="${REQUIRED},llama3.1:8b,qwen3.5:9b,qwen2.5:14b,deepseek-r1:14b"
  else
    REQUIRED="${REQUIRED},llama3.1:8b,qwen3.5:9b,qwen2.5:14b,deepseek-r1:14b,gemma4:12b"
  fi

  if [ "$PULL_ACCURACY" = "true" ]; then
    if [ "$VRAM_MB" -ge 20000 ]; then
      ACCURACY="${ACCURACY},qwen2.5:32b"
    fi
    if [ "$VRAM_MB" -ge 24000 ]; then
      ACCURACY="${ACCURACY},deepseek-r1:32b"
    fi
    if [ "$VRAM_MB" -ge 40000 ]; then
      ACCURACY="${ACCURACY},qwen2.5:72b"
    fi
  fi

  # Configured role models: include when they fit the same VRAM budget.
  for extra in \
    "${LLM_PRIMARY_MODEL:-}" \
    "${LLM_REVIEW_MODEL:-}" \
    "${LLM_REVIEW_MODEL_LARGE:-}" \
    "${LLM_FAST_MODEL:-}" \
    "${RAG_EMBEDDING_FALLBACK:-}" \
    "${AGENT_MODEL:-}" \
    "${GAP_REPORT_LLM_MODEL:-}" \
    "${MOBILE_REPORT_LLM_MODEL:-}" \
    "${MOBILE_REPORT_LLM_FALLBACK_MODEL:-}"
  do
    [ -z "$extra" ] && continue
    case ",${REQUIRED},${ACCURACY}," in
      *",$extra,"*) ;;
      *) REQUIRED="${REQUIRED},${extra}" ;;
    esac
  done

  if [ -n "${OLLAMA_PULL_MODELS:-}" ]; then
    OLD_IFS=$IFS
    IFS=,
    for extra in $OLLAMA_PULL_MODELS; do
      extra=$(echo "$extra" | tr -d ' ')
      [ -z "$extra" ] && continue
      case ",${REQUIRED},${ACCURACY}," in
        *",$extra,"*) ;;
        *) REQUIRED="${REQUIRED},${extra}" ;;
      esac
    done
    IFS=$OLD_IFS
  fi
fi

MODELS="${REQUIRED}${ACCURACY}"
echo "Required: ${REQUIRED}"
echo "Accuracy extras: ${ACCURACY:-none}"
echo "Models to ensure: ${MODELS}"

echo "Waiting for Ollama at ${OLLAMA_HOST}..."
i=0
until ollama list >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 120 ]; then
    echo "Ollama did not become ready in time" >&2
    exit 1
  fi
  sleep 2
done
echo "Ollama is up."

pull_one() {
  model="$1"
  [ -z "$model" ] && return 0
  echo "Ensuring model: ${model}"
  if ollama list 2>/dev/null | grep -Fq "$model"; then
    echo "  already present: ${model}"
    return 0
  fi
  ollama pull "$model" || {
    echo "  pull failed for ${model} (retry once)"
    sleep 5
    ollama pull "$model" || echo "  skip after retry: ${model}"
  }
}

OLD_IFS=$IFS
IFS=,
for model in $MODELS; do
  model=$(echo "$model" | tr -d ' ')
  pull_one "$model"
done
IFS=$OLD_IFS

echo "Ollama model ensure complete (VRAM=${VRAM_MB}MB)."
ollama list || true
