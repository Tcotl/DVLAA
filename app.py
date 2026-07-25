"""Backward-compatible launcher for the structured :mod:`dvlaa` package.

Use ``python -m dvlaa`` for the canonical entry point.
"""

from dvlaa.server import app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
