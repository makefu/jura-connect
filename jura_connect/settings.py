"""Single-write setting transaction with lossless primary-error handling."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from .timers import require_supported

if TYPE_CHECKING:
    from .client import JuraClient


class SettingRejectedError(ValueError):
    """The machine explicitly rejected the lock or setting write."""


class SettingUncertainError(ValueError):
    """A write or keypad release was not confirmed; read back before retrying."""


def locked_setting_write(
    client: JuraClient,
    body: str,
    *,
    timeout: float,
    before_write: Callable[[], None] | None = None,
) -> str:
    """Lock, send at most one write, and always attempt keypad release.

    Preserve the original exception, including a caller guard or TimeoutError.
    A secondary unlock failure is attached as a note to that exception.
    """
    from .client import _settings_checksum

    require_supported(client)
    primary: BaseException | None = None
    state = "No setting write sent"
    try:
        if (
            client.request(
                "@TS:01", match=r"(?i)^@(ts|an)(?::|$)", timeout=timeout
            ).lower()
            != "@ts"
        ):
            raise SettingRejectedError(
                "Machine rejected the keypad lock; no setting write sent"
            )
        if before_write is not None:
            before_write()
        state = "Setting write may have been applied; read back before retrying"
        reply = client.request(
            f"@TM:{body}{_settings_checksum(body)}",
            match=r"(?i)^@(tm|an):",
            timeout=timeout,
        )
        if reply.lower() == "@an:error":
            state = "Machine explicitly rejected the setting write"
            raise SettingRejectedError("Machine rejected the setting write: @an:error")
        if reply.lower() != f"@tm:{body.split(',', 1)[0].lower()}":
            raise SettingUncertainError(
                f"Machine did not acknowledge the setting write: {reply!r}; read back before retrying"
            )
        return reply
    except BaseException as exc:
        primary = exc
        if isinstance(exc, TimeoutError):
            exc.add_note(state)
        raise
    finally:
        try:
            unlocked = client.request(
                "@TS:00", match=r"(?i)^@(ts|an)(?::|$)", timeout=timeout
            )
            if unlocked.lower() != "@ts":
                raise SettingUncertainError(
                    f"Keypad unlock not confirmed: {unlocked!r}. {state}"
                )
        except BaseException as unlock_error:
            if primary is not None:
                primary.add_note(
                    f"Keypad unlock also failed: {unlock_error!r}. {state}"
                )
            else:
                if isinstance(unlock_error, TimeoutError):
                    unlock_error.add_note(f"Keypad unlock not confirmed. {state}")
                    raise
                if isinstance(unlock_error, OSError):
                    raise SettingUncertainError(
                        f"Keypad unlock not confirmed. {state}"
                    ) from unlock_error
                raise
