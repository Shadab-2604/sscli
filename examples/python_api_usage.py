"""Example of programmatically initializing and interacting with the systemscan core API."""

from systemscan.app import create_app
from systemscan.version import __version__


def main() -> None:
    print(f"Initializing systemscan v{__version__} programmatically...")
    app = create_app()
    app.bootstrap(verbose=True)

    print(f"Platform: {app.platform.os_name} ({app.platform.architecture})")
    print(f"Is elevated/admin: {app.platform.is_elevated()}")
    print(f"Config path: {app.paths.config_file}")
    print(f"Worker count: {app.config.scanner.worker_count}")
    print(f"Log level: {app.config.log_level}")

    print("\nProgrammatic initialization test completed successfully.")


if __name__ == "__main__":
    main()
