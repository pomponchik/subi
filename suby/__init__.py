import sys

from suby.proxy_module import ProxyModule as ProxyModule
from suby.errors import RunningCommandError as RunningCommandError, WrongCommandError as WrongCommandError  # noqa: F401

from cantok import TimeoutCancellationError as TimeoutCancellationError  # noqa: F401


sys.modules[__name__].__class__ = ProxyModule
