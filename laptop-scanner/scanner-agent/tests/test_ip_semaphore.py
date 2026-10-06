from agent.ip_semaphore import AdaptiveIPSemaphore


def test_semaphore_never_exceeds_live_limit():
    sem = AdaptiveIPSemaphore(max_permits=10)
    assert [sem.try_acquire(5) for _ in range(6)] == [True, True, True, True, True, False]
    assert sem.active == 5
    sem.release()
    assert sem.try_acquire(5) is True
    assert sem.active == 5


def test_dynamic_shrink_waits_for_existing_holders():
    sem = AdaptiveIPSemaphore(max_permits=10)
    for _ in range(8):
        assert sem.try_acquire(8)
    assert not sem.try_acquire(5)
    for _ in range(4):
        sem.release()
    assert sem.active == 4
    assert sem.try_acquire(5)
    assert sem.active == 5


def test_restore_counts_resumed_tasks():
    sem = AdaptiveIPSemaphore(max_permits=10)
    sem.restore(6)
    assert sem.active == 6
    assert not sem.try_acquire(5)
    sem.release()
    sem.release()
    assert sem.try_acquire(5)
