# Proposed data dictionary

These fields are discussion starters, not a finalized schema. Record units and missing-value rules before collection.

| Field | Meaning |
|---|---|
| scan_id | Unique acquisition record identifier |
| session_id | Identifier shared by observations in a controlled session |
| physical_source_id | Lab identifier for the physical card or emulation source; do not rely on UID alone |
| reader_id | Reader or device identifier |
| firmware_version | Acquisition firmware version |
| card_type | Card or tag technology |
| timestamp_utc | Acquisition time in UTC |
| label | Ground-truth lab class, where independently known |
| protocol_response | Observed response and status; representation to be agreed |
| timing_value | Measured timing, when supported, with unit and measurement boundary |

C2 split definitions must preserve physical-source and session grouping as required by the experimental design. Avoid putting observations from the same controlled source/session into incompatible partitions.
