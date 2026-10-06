#!/bin/sh
for p in /proc/[0-9]*; do
  if [ -r "$p/cmdline" ]; then
    cmd=$(tr '\0' ' ' < "$p/cmdline")
    echo "PID=$(basename "$p") CMD=$cmd"
  fi
done
which gdb || true
which python || which python3
