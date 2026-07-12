"""SDK exceptions."""

from __future__ import annotations

from typing import Any


class GuardBandsError(Exception):
    """Base class for SDK errors."""


class GuardBandsAPIError(GuardBandsError):
    """Raised when the Guard Bands API returns an unsuccessful HTTP response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        detail: Any = None,
        response_body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.response_body = response_body


class AuthenticationError(GuardBandsAPIError):
    """Authentication failed or credentials were missing."""


class AuthorizationError(GuardBandsAPIError):
    """The authenticated principal is not allowed to perform the action."""


class NotFoundError(GuardBandsAPIError):
    """The requested API path or resource does not exist."""


class RateLimitError(GuardBandsAPIError):
    """The API rejected the request due to rate limiting."""


class VerificationFailed(GuardBandsAPIError):
    """Guard Band verification failed."""


class CostThresholdExceeded(GuardBandsAPIError):
    """A chat request exceeded the configured preflight cost threshold."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        detail: Any = None,
        response_body: Any = None,
        cost_estimate: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            detail=detail,
            response_body=response_body,
        )
        self.cost_estimate = cost_estimate
