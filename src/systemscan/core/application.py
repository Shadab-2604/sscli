"""Central application container and bootstrap coordinator for systemscan."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from systemscan.config.manager import ConfigManager
from systemscan.config.schema import SystemScanConfig
from systemscan.core.constants import ExitCode, LogLevel
from systemscan.core.dependencies import DependencyRegistry, dependency_registry
from systemscan.core.error_handler import ErrorHandler, error_handler
from systemscan.core.lifecycle import LifecycleManager, LifecycleState
from systemscan.logging.logger import get_logger, init_logging, set_log_level
from systemscan.utils.paths import AppPaths, paths
from systemscan.version import APP_NAME, __version__

if TYPE_CHECKING:
    from systemscan.platform.base import PlatformInterface

logger = get_logger("application")


class Application:
    """Core application container orchestrating state, config, paths, platform, and lifecycle."""

    def __init__(
        self,
        app_paths: AppPaths | None = None,
        config_manager: ConfigManager | None = None,
        platform_handler: PlatformInterface | None = None,
        dep_registry: DependencyRegistry | None = None,
        err_handler: ErrorHandler | None = None,
    ) -> None:
        self.paths = app_paths or paths
        self.config_manager = config_manager or ConfigManager(self.paths)

        if platform_handler is not None:
            self.platform = platform_handler
        else:
            from systemscan.platform import current_platform

            self.platform = current_platform

        self.dependencies = dep_registry or dependency_registry
        self.error_handler = err_handler or error_handler
        self.lifecycle = LifecycleManager()

        self._config: SystemScanConfig | None = None
        self._debug_mode: bool = False
        self._verbose_mode: bool = False

    @property
    def config(self) -> SystemScanConfig:
        """Active application configuration."""
        if self._config is None:
            self._config = self.config_manager.current
        return self._config

    @property
    def is_debug(self) -> bool:
        """Whether debug mode is active."""
        return self._debug_mode

    @property
    def is_verbose(self) -> bool:
        """Whether verbose mode is active."""
        return self._verbose_mode

    def reset(self) -> None:
        """Reset application state for testing or restart."""
        self.lifecycle = LifecycleManager()
        self._config = None

    def bootstrap(
        self,
        debug: bool = False,
        verbose: bool = False,
        log_level_override: str | None = None,
        force: bool = False,
    ) -> None:
        """Bootstrap the application foundation in strict sequence.

        1. Initialize preliminary logging
        2. Resolve application paths and ensure directories
        3. Install signal handlers (SIGINT/Ctrl+C)
        4. Load and validate configuration
        5. Reconfigure logging according to user config/flags
        6. Verify core dependencies
        7. Transition lifecycle to READY
        """
        if not force and self.lifecycle.state in (
            LifecycleState.CONFIGURED,
            LifecycleState.READY,
            LifecycleState.RUNNING,
        ):
            return

        self.lifecycle.transition_to(LifecycleState.INITIALIZING)
        self._debug_mode = debug
        self._verbose_mode = verbose
        self.error_handler.set_debug(debug)

        # 1. Preliminary logging setup
        prelim_level = LogLevel.DEBUG if debug else LogLevel.INFO
        init_logging(
            level=prelim_level,
            app_paths=self.paths,
            debug=debug,
            console_enabled=True,
            file_enabled=True,
        )
        logger.info(f"Starting {APP_NAME} v{__version__}...")
        logger.debug(f"Detected Platform: {self.platform.os_name} ({self.platform.architecture})")

        # 2. Ensure system directories exist
        self.paths.ensure_directories()
        logger.debug(f"Resolved paths: config={self.paths.config_dir}, data={self.paths.data_dir}")

        # 3. Install signal traps for graceful Ctrl+C
        self.lifecycle.install_signal_handlers()

        # 4. Load configuration
        try:
            self._config = self.config_manager.load_or_initialize()
            self.lifecycle.transition_to(LifecycleState.CONFIGURED)
            logger.debug("Configuration loaded and validated successfully.")
        except Exception as e:
            logger.error(f"Configuration bootstrap failed: {e}")
            raise

        # 5. Fine-tune logging from configuration
        chosen_level = log_level_override or (
            LogLevel.DEBUG.value if debug else self._config.log_level.value
        )
        set_log_level(chosen_level)

        # Register cleanup hook for application shutdown
        self.lifecycle.register_cleanup(
            "app_shutdown_log",
            lambda: logger.info("Application session ended."),
        )

        # 6. Verify dependencies
        all_ok, missing = self.dependencies.verify_required()
        if not all_ok:
            logger.warning(f"Found {len(missing)} unfulfilled dependencies.")

        # 7. Transition to READY
        self.lifecycle.transition_to(LifecycleState.READY)
        logger.debug("Application bootstrap sequence completed successfully.")

    def run_safe(self, action: Any, *args: Any, **kwargs: Any) -> int:
        """Execute a callable within the protected lifecycle context."""
        try:
            if self.lifecycle.state == LifecycleState.READY:
                self.lifecycle.transition_to(LifecycleState.RUNNING)

            result = action(*args, **kwargs)
            exit_code = result if isinstance(result, int) else ExitCode.SUCCESS

            self.lifecycle.shutdown(exit_code=ExitCode(exit_code))
            return exit_code
        except BaseException as e:
            exit_code = self.error_handler.handle_exception(e)
            self.lifecycle.shutdown(exit_code=ExitCode(exit_code))
            return exit_code


# Global application container instance
app_instance = Application()
