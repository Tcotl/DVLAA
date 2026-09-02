"""Standalone local AWDP target-service runtime.

The DVLAA console is only the session-aware gateway.  The service in this
package owns the HTTP contract and executes the vulnerable/repaired handler
for each challenge in an isolated target session.
"""

