# Aetheris Laptop Scanner v1.4.8 - Greenbone GMP count/readiness fix

## Symptom

OSPd reports `Finished loading VTs`, while the scanner readiness probe reports:

```json
{"ready":false,"reason":"nvt_count_unavailable","nvt_count":-1,...}
```

and queued jobs remain at 5%.

## Root cause

On current Greenbone/python-gvm combinations, `get_nvts()` can be implemented through GMP `get_info` unless `extended=True` is requested. The response may therefore expose `info_count` instead of `nvt_count`, or can expose NVT objects/feed versions without a total-count element. v1.4.7 treated the missing total count as proof that the feed was still loading, causing a false-negative readiness state.

## Fix

v1.4.8:

1. requests `get_nvts(..., extended=True)` first;
2. understands both `nvt_count` and `info_count` response schemas;
3. treats positive NVT inventory + feed versions as inventory-ready when the total count is unavailable;
4. still requires the configured `Full and fast` scan configuration before `LocalOpenVAS.ready()` returns true;
5. preserves the minimum-count fail-closed gate whenever a trustworthy count is available;
6. does not restart ospd-openvas or delete Greenbone volumes.

This keeps incomplete feeds blocked while avoiding a permanent queue caused only by a GMP response-shape difference.
