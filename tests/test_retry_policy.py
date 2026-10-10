from layers.recovery.retry_policy import RetryVerdict, decide_retry


def test_idempotent_transient_is_safe_retry():
    pol = decide_retry(
        idempotent=True,
        has_idempotency_key=False,
        transient=True,
        completion_known=False,
        completed=False,
    )
    assert pol.verdict == RetryVerdict.SAFE_RETRY


def test_non_idempotent_without_key_is_check_then_retry():
    pol = decide_retry(
        idempotent=False,
        has_idempotency_key=False,
        transient=True,
        completion_known=False,
        completed=False,
    )
    assert pol.verdict == RetryVerdict.CHECK_THEN_RETRY


def test_non_idempotent_with_idempotency_key_is_safe_retry():
    pol = decide_retry(
        idempotent=False,
        has_idempotency_key=True,
        transient=True,
        completion_known=False,
        completed=False,
    )
    assert pol.verdict == RetryVerdict.SAFE_RETRY


def test_operation_already_completed_is_do_not_retry():
    pol = decide_retry(
        idempotent=False,
        has_idempotency_key=False,
        transient=True,
        completion_known=True,
        completed=True,
    )
    assert pol.verdict == RetryVerdict.DO_NOT_RETRY


def test_non_transient_error_is_do_not_retry():
    pol = decide_retry(
        idempotent=True,
        has_idempotency_key=False,
        transient=False,
        completion_known=False,
        completed=False,
    )
    assert pol.verdict == RetryVerdict.DO_NOT_RETRY
