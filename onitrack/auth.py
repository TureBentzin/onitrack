from __future__ import annotations

import asyncio
import getpass
import inspect
import os
from pathlib import Path
from typing import Any

from onitrack.state import (
    account_state_path,
    ensure_state_dir,
    read_json,
    sanitize_account_state,
    state_status,
    write_json_atomic,
)

ANISETTE_LIBS_ENV = "ONITRACK_ANISETTE_LIBS"


def provision(state_dir: Path) -> int:
    state_dir = ensure_state_dir(state_dir)
    account_path = account_state_path(state_dir)
    account = _load_or_create_account(account_path)

    if _login_state_name(account.login_state) == "LOGGED_IN":
        _save_account(account_path, account)
        _close_account(account)
        print("account: logged_in")
        return 0

    username = input("Apple Account: ").strip()
    password = getpass.getpass("Apple Account password: ")

    try:
        login_state = account.login(username, password)
        if _login_state_name(login_state) == "REQUIRE_2FA":
            login_state = _complete_2fa(account)

        if _login_state_name(login_state) != "LOGGED_IN":
            print(f"account: {_login_state_name(login_state).lower()}")
            return 1

        _save_account(account_path, account)
        print("account: logged_in")
        return 0
    finally:
        _close_account(account)


def print_status(state_dir: Path) -> int:
    status = state_status(state_dir)
    print(f"account: {status['account']}")
    print(f"state_dir: {status['state_dir']}")
    print(f"account_file: {status['account_file']}")
    print(f"password_persisted: {status['password_persisted']}")
    return 0


def _load_or_create_account(account_path: Path) -> Any:
    from findmy import AppleAccount, LocalAnisetteProvider

    libs_path = _anisette_libs_path()
    state = read_json(account_path)
    if state is not None:
        return AppleAccount.from_json(state, anisette_libs_path=libs_path)

    anisette = LocalAnisetteProvider(libs_path=libs_path)
    return AppleAccount(anisette)


def _complete_2fa(account: Any) -> Any:
    from findmy import SmsSecondFactorMethod, TrustedDeviceSecondFactorMethod

    methods = list(account.get_2fa_methods())
    if not methods:
        msg = "Apple requested 2FA but FindMy.py returned no supported methods."
        raise RuntimeError(msg)

    print("Two-factor methods:")
    for index, method in enumerate(methods):
        if isinstance(method, TrustedDeviceSecondFactorMethod):
            label = "Trusted Device"
        elif isinstance(method, SmsSecondFactorMethod):
            label = f"SMS ({method.phone_number})"
        else:
            label = method.__class__.__name__
        print(f"{index} - {label}")

    method_index = _prompt_method_index(len(methods))
    method = methods[method_index]
    method.request()
    code = input("Code: ").strip()
    return method.submit(code)


def _prompt_method_index(method_count: int) -> int:
    while True:
        raw_value = input("Method: ").strip()
        try:
            index = int(raw_value)
        except ValueError:
            print("Enter a numeric method index.")
            continue

        if 0 <= index < method_count:
            return index
        print("Method index out of range.")


def _save_account(account_path: Path, account: Any) -> None:
    state = sanitize_account_state(account.to_json())
    write_json_atomic(account_path, state)


def _close_account(account: Any) -> None:
    close_result = account.close()
    if inspect.isawaitable(close_result):
        asyncio.run(close_result)


def _login_state_name(login_state: Any) -> str:
    return str(getattr(login_state, "name", login_state))


def _anisette_libs_path() -> Path | None:
    raw_path = os.environ.get(ANISETTE_LIBS_ENV)
    return Path(raw_path) if raw_path else None
