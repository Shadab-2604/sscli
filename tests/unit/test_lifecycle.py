"""Unit tests for application lifecycle state machine."""

import pytest

from systemscan.core.constants import ExitCode
from systemscan.core.exceptions import LifecycleError
from systemscan.core.lifecycle import LifecycleManager, LifecycleState


def test_valid_lifecycle_transitions() -> None:
    lm = LifecycleManager()
    assert lm.state == LifecycleState.CREATED

    lm.transition_to(LifecycleState.INITIALIZING)
    assert lm.state == LifecycleState.INITIALIZING

    lm.transition_to(LifecycleState.CONFIGURED)
    assert lm.state == LifecycleState.CONFIGURED

    lm.transition_to(LifecycleState.READY)
    assert lm.state == LifecycleState.READY

    lm.transition_to(LifecycleState.RUNNING)
    assert lm.state == LifecycleState.RUNNING

    lm.transition_to(LifecycleState.SHUTTING_DOWN)
    assert lm.state == LifecycleState.SHUTTING_DOWN

    lm.transition_to(LifecycleState.TERMINATED)
    assert lm.state == LifecycleState.TERMINATED


def test_invalid_lifecycle_transition() -> None:
    lm = LifecycleManager()
    with pytest.raises(LifecycleError):
        # Cannot jump from CREATED directly to RUNNING
        lm.transition_to(LifecycleState.RUNNING)


def test_cleanup_callbacks() -> None:
    lm = LifecycleManager()
    cleaned = []

    lm.register_cleanup("hook1", lambda: cleaned.append("hook1"))
    lm.register_cleanup("hook2", lambda: cleaned.append("hook2"))

    lm.transition_to(LifecycleState.INITIALIZING)
    lm.shutdown(ExitCode.SUCCESS)

    # Cleanups execute in reverse registration order
    assert cleaned == ["hook2", "hook1"]
    assert lm.state == LifecycleState.TERMINATED
