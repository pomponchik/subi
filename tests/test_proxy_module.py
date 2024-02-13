import sys
from time import perf_counter
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr

import pytest
from cantok import TimeoutCancellationError
from emptylog import MemoryLogger

import suby
from suby import RunningCommandError


def test_normal_way():
    result = suby(sys.executable, '-c', 'print("kek")')

    assert result.stdout == 'kek\n'
    assert result.stderr == ''
    assert result.returncode == 0


def test_stderr_catching():
    result = suby(sys.executable, '-c', 'import sys; sys.stderr.write("kek")')

    assert result.stdout == ''
    assert result.stderr == 'kek'
    assert result.returncode == 0


def test_catch_exception():
    result = suby(sys.executable, '-c', 'raise ValueError', catch_exceptions=True)

    assert 'ValueError' in result.stderr
    assert result.returncode != 0


def test_timeout():
    sleep_time = 100000
    timeout = 0.001

    start_time = perf_counter()
    result = suby(sys.executable, '-c', f'import time; time.sleep({sleep_time})', timeout=timeout, catch_exceptions=True)
    end_time = perf_counter()

    assert result.returncode != 0
    assert result.stdout == ''
    assert result.stderr == ''

    assert (end_time - start_time) < sleep_time
    assert (end_time - start_time) >= timeout


def test_timeout_without_catching_exception():
    sleep_time = 100000
    timeout = 0.001

    with pytest.raises(TimeoutCancellationError):
        suby(sys.executable, '-c', f'import time; time.sleep({sleep_time})', timeout=timeout)

    start_time = perf_counter()
    try:
        result = suby(sys.executable, '-c', f'import time; time.sleep({sleep_time})', timeout=timeout)
    except TimeoutCancellationError as e:
        assert e.result.stdout == ''
        assert e.result.stderr == ''
        assert e.result.returncode != 0
    end_time = perf_counter()

    assert (end_time - start_time) < sleep_time
    assert (end_time - start_time) >= timeout


def test_exception_in_subprocess_without_catching():
    with pytest.raises(RunningCommandError, match=f'Error when executing the command "{sys.executable} -c "raise ValueError"".'):
        suby(sys.executable, '-c', 'raise ValueError')

    try:
        suby(sys.executable, '-c', 'raise ValueError')
    except RunningCommandError as e:
        assert e.result.stdout == ''
        assert 'ValueError' in e.result.stderr
        assert e.result.returncode != 0


def test_not_catching_output():
    stderr_buffer = StringIO()
    stdout_buffer = StringIO()

    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        result = suby(sys.executable, '-c', 'print("kek1", end=""); import sys; sys.stderr.write("kek2")', catch_output=False)

        stderr = stderr_buffer.getvalue()
        stdout = stdout_buffer.getvalue()

        assert result.returncode == 0
        assert stderr == 'kek2'
        assert stdout == 'kek1'


def test_catching_output():
    stderr_buffer = StringIO()
    stdout_buffer = StringIO()

    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        result = suby(sys.executable, '-c', 'print("kek1", end=""); import sys; sys.stderr.write("kek2")', catch_output=True)

        assert result.returncode == 0
        assert stderr_buffer.getvalue() == ''
        assert stdout_buffer.getvalue() == ''


def test_logging_normal_way():
    logger = MemoryLogger()

    suby(sys.executable, '-c', 'print("kek", end="")', logger=logger, catch_output=True)

    assert len(logger.data.info) == 2
    assert len(logger.data.error) == 0

    assert logger.data.info[0].message == f'The beginning of the execution of the command "{sys.executable} -c "print("kek", end="")"".'
    assert logger.data.info[1].message == f'The command "{sys.executable} -c "print("kek", end="")"" has been successfully executed.'


def test_logging_with_timeout():
    logger = MemoryLogger()

    suby(sys.executable, '-c', f'import time; time.sleep({500_000})', logger=logger, catch_exceptions=True, catch_output=True, timeout=0.0001)

    assert len(logger.data.info) == 1
    assert len(logger.data.error) == 1

    assert logger.data.info[0].message == f'The beginning of the execution of the command "{sys.executable} -c "import time; time.sleep(500000)"".'
    assert logger.data.error[0].message == f'The execution of the "{sys.executable} -c "import time; time.sleep(500000)"" command was canceled using a cancellation token.'
