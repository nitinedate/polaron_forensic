# Aetheris Laptop Scanner v1.4.9 - queued jobs / agent instance ownership fix

Root cause: central queue fencing (introduced in the edge-owner protocol) requires an `X-Aetheris-Agent-Instance` value for registered scanner versions >= 1.2.22. Laptop v1.4.8 authenticated successfully and polled `/jobs/next`, but it did not send an instance id, so central intentionally returned `{"job": null}` and every UI job stayed queued.

v1.4.9 adds a stable non-secret agent instance id stored at `/run/aetheris-agent/agent-instance-id`, sends it in the `X-Aetheris-Agent-Instance` header, and also sends `agent_instance_id` as a query fallback for proxies that strip custom headers. The same identity is sent on job progress and result upload calls.

The startup script also fails fast if the durable runtime agent token is missing or zero bytes after binding.

No Greenbone/PostgreSQL/Redis volumes are deleted or recreated.
