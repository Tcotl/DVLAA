# Handoff window lifecycle

A sender registers an asset, records a shift observation, and opens a
time-bounded handoff window for a named receiver. The shift lead decision
precedes receiver acknowledgement. A completed export writes a receipt that
binds the window to the delivered asset.

The board shows owned assets, submitted observations, and windows started by
the authenticated shift. A receiver only sees the acknowledgement addressed
to that receiver.
