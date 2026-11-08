"""Configuration validation routines for systemscan."""

from typing import Any

from pydantic import ValidationError

from systemscan.config.schema import SystemScanConfig
from systemscan.core.exceptions import ConfigValidationError


class ConfigValidator:
    """Validates configuration payloads against defined schema."""

    @classmethod
    def validate_dict(cls, data: dict[str, Any]) -> SystemScanConfig:
        """Validate a configuration dictionary and return validated model."""
        if not isinstance(data, dict):
            raise ConfigValidationError(
                f"Configuration root must be a dictionary/object, got {type(data).__name__}."
            )

        try:
            return SystemScanConfig.model_validate(data)
        except ValidationError as e:
            error_details: list[str] = []
            for err in e.errors():
                loc = ".".join(str(p) for p in err["loc"])
                msg = err["msg"]
                error_details.append(f"Field '{loc}': {msg}")

            summary = "; ".join(error_details)
            raise ConfigValidationError(
                f"Configuration validation failed: {summary}",
                details={"errors": e.errors()},
            ) from e
