import asyncio
import sys
import types

from onitrack.auth import _close_account, _profiled_anisette_provider


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


def test_profiled_anisette_uses_synthetic_mac_profile(monkeypatch, tmp_path):
    captured = {}

    class FakeLocalAnisetteProvider:
        def __init__(self, *, libs_path):
            captured["libs_path"] = libs_path

        async def get_headers(
            self,
            user_id,
            device_id,
            serial="0",
            with_client_info=False,
        ):
            captured["serial"] = serial
            captured["with_client_info"] = with_client_info
            return {"X-Apple-I-SRL-NO": serial}

    monkeypatch.setitem(
        sys.modules,
        "findmy",
        types.SimpleNamespace(LocalAnisetteProvider=FakeLocalAnisetteProvider),
    )
    provider = _profiled_anisette_provider(
        tmp_path / "libs.tar",
        {
            "hardware_version": "MacTest1,1",
            "serial_number": "SYNTHETIC-SERIAL",
            "software_build_id": "99Z999",
            "software_name": "macOS",
            "software_version": "99.1",
        },
    )

    headers = asyncio.run(provider.get_headers("user", "device"))

    assert headers["X-Apple-I-SRL-NO"] == "SYNTHETIC-SERIAL"
    assert captured["serial"] == "SYNTHETIC-SERIAL"
    assert provider.client.startswith("<MacTest1,1> <macOS;99.1;99Z999>")
    assert "com.apple.accountsd/113" in provider.mobileme_client
