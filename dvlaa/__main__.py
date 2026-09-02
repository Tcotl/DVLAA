"""Run the DVLAA web console with ``python -m dvlaa``."""

from .config import DEBUG, PORT
from .server import app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT or 5000, debug=DEBUG)
