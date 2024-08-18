from suby.errors import RunningCommandError
from suby.subprocess_result import SubprocessResult


def test_init_exception_and_raise():
    result = SubprocessResult()
    try:
        raise RunningCommandError('kek', result)
    except RunningCommandError as e:
        assert str(e) == 'kek'
        assert e.result is result
