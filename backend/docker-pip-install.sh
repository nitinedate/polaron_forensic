#!/bin/sh
# Install Python deps without pulling PyPI CUDA/NCCL wheels (200MB+, SSL-fragile).
set -eu
TORCH_INDEX_URL="${TORCH_INDEX_URL:-https://download.pytorch.org/whl/cpu}"

python -m pip install --upgrade pip --retries 20 --timeout 180
python -m pip install --retries 20 --timeout 180 torch torchvision --index-url "${TORCH_INDEX_URL}"
python -c "import importlib.metadata as m; open('/tmp/torch-pin.txt','w').write('torch==%s\ntorchvision==%s\n' % (m.version('torch'), m.version('torchvision')))"

i=1
until python -m pip install --retries 20 --timeout 180 -r requirements.txt -c /tmp/torch-pin.txt; do
  i=$((i + 1))
  if [ "$i" -gt 6 ]; then
    echo "pip install failed after 6 attempts" >&2
    exit 1
  fi
  echo "pip retry ${i}/6 after SSL/network error"
  sleep 15
done
