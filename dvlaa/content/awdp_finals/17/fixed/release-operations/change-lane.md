# Release operations lane

This packet describes the source-assisted review surface for the Release
Control Tower. The service is already hosted at the address supplied by the
event platform. Use the packet to inspect the business behavior and prepare a
safe change within the existing service.

## Business context

The tower accepts a change manifest for a service, records its prose and
extension fields, sends the manifest through a review queue, and creates a
preflight job for an approved release. The job result is available through the
same subject and tenant that submitted the manifest.

## Normal lane

1. Create a low-privilege session with the public registration endpoint.
2. Submit a manifest containing a service name, a change description, and the
   requested extension text.
3. Reviewers move an eligible manifest through the review queue.
4. Request one preflight for the manifest and retain the returned run and job
   references.
5. Poll the job reference and review the recorded change history.

The service keeps the manifest, review history, signed tool registry, job
state, and change note as separate business records. A normal client should
use the identifiers returned by the service instead of constructing them.

## Field contract

| Field | Meaning |
| --- | --- |
| `service` | The service represented by the change manifest. |
| `prose` | Human-readable change context. |
| `extension` | The requested extension description associated with the change. |
| `manifest_id` | The server-created manifest reference. |
| `run_id` | The server-created Agent run reference. |
| `job_id` | The server-created preflight job reference when a job is created. |

## Review surface

`preflight_control.py` contains the manifest, review, registry, and job
operations. `preflight_rail.py` contains the durable Agent rail, readiness
context, change-note memory, and the three business phases used by the
service. Read the two modules together with the public responses when tracing
ownership, state transitions, and result handling.

## Expected service behavior

- Imported prose and extension text remain ordinary manifest data.
- A high-impact operation uses an approved business context and a registered
  action.
- A job, its output, and its change note remain bound to the submitting
  subject and tenant.
- Repeated requests and unknown references return an explicit service error.
- A normal reviewed preflight remains available after a safe implementation
  change.
