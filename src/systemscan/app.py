"""Top-level application facade for systemscan."""

from systemscan.core.application import Application, app_instance


def create_app() -> Application:
    """Create and return a new Application instance."""
    return Application()


# Default singleton instance
app = app_instance

__all__ = ["Application", "app", "create_app"]
