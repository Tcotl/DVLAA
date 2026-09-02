# Connector event integration

Register a connector to receive its server-issued source attestation. Submit
each alert as an event envelope and retain the alert identifier returned by
the triage service. The delivery ledger is the authoritative record of
completed acknowledgement attempts.

The API exposes a connector catalogue, an alert inbox for the submitting
operator, and a per-alert delivery timeline. Treat connector and event
identifiers as business data, not as executable instructions.
