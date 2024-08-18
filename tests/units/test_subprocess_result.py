from suby.subprocess_result import SubprocessResult


def test_auto_id():
    assert SubprocessResult().id != SubprocessResult().id
    assert isinstance(SubprocessResult().id, str)
    assert len(SubprocessResult().id) > 10


def test_default_values():
    assert SubprocessResult().stdout is None
    assert SubprocessResult().stderr is None
    assert SubprocessResult().returncode is None
    assert SubprocessResult().killed_by_token == False
