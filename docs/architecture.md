# Planned architecture

Shared acquisition utilities collect reader observations. Each component consumes agreed records and produces its own results. The backend is planned to store and associate records; the dashboard will present the integrated outputs.

| Layer | Responsibility |
|---|---|
| Acquisition | Proxmark3, Flipper Zero, and supported smartphone collection |
| C1 | Capability-aware security scoring |
| C2 | Multi-session protocol-response provenance classification |
| C3 | Baseline-based tag integrity verification |
| C4 | Rules and model-based behavioural anomaly detection |
| Backend | Record storage and component coordination |
| Dashboard | Unified display of component outputs |

These are intended responsibilities; interfaces and technologies are not implemented yet.
