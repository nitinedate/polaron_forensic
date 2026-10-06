# Aetheris Laptop Scanner v1.5.0 final

Built on v1.4.9 queue/ownership and performance fixes. This release keeps concurrency/throughput unchanged and corrects vulnerability result fidelity:

- robust Greenbone CVSS extraction (including per-result severity and newer NVT severity nodes);
- Nessus CVSS severity bands only;
- exact host attribution, all CVEs/references, QoD and raw Greenbone fields preserved;
- agent version 1.5.0.

Install as a fresh laptop package or apply the smaller v1.5.0 data-fidelity hotfix to an existing v1.4.9 installation.
