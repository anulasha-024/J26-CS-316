# Integration plan

1. Agree on versioned acquisition and result schemas.
2. Implement and validate shared reader collection.
3. Implement component adapters and independent evaluations.
4. Connect storage and orchestration in the backend.
5. Present results in the dashboard and add integration checks.

Each component result should identify its input scan/session, component, implementation/model version, outcome, and relevant evidence. Confidence values should be included only if the component actually computes and validates them.

Changes to shared interfaces should be reviewed by affected component members before merging.
