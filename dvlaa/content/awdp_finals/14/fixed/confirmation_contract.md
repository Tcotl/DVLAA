# Delivery confirmation protocol

A dispatch operator creates an order with an address and a driver note. The
order remains at its recorded version until its recipient confirmation is
captured. A redirection creates a new version and an immutable dispatch
receipt. Repeating a completed instruction must return the original receipt
instead of creating another delivery transition.

The confirmation record identifies the order, its current version, and the
recipient-side acknowledgement that was collected before the change window.
