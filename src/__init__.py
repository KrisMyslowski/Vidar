"""Vidar — passive visitor intelligence for a single web server."""

# The version the running service reports, and the only place it is written.
# deploy/Dockerfile copies requirements/runtime.txt and src/ and nothing else,
# so pyproject.toml is absent from the image: reading the version from there —
# directly or through importlib.metadata — works on a workstation and raises in
# production. tests/test_version.py holds the two in step.
__version__ = "1.0.0"
