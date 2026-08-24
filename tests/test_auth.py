import asyncio

from onitrack.auth import _close_account


def test_close_account_uses_account_event_loop():
    class Account:
        def __init__(self):
            self._evt_loop = asyncio.new_event_loop()
            self.closed_loop = None

        async def close(self):
            self.closed_loop = asyncio.get_running_loop()

    account = Account()
    try:
        _close_account(account)

        assert account.closed_loop is account._evt_loop
    finally:
        account._evt_loop.close()
