from __future__ import annotations

import asyncio
import getpass
import inspect
import os
import shutil
from pathlib import Path
from typing import Any

from onitrack.state import (
    CONFIG_FILE_MODE,
    account_config_path,
    config_status,
    ensure_config_dir,
    read_json,
    sanitize_account_state,
    write_json_atomic,
)

ANISETTE_LIBS_TEMPLATE_ENV = "ONITRACK_ANISETTE_LIBS_TEMPLATE"
ANISETTE_LIBS_FILE = "anisette-libs.tar"


def provision(config_dir: Path) -> int:
    config_dir = ensure_config_dir(config_dir)
    account_path = account_config_path(config_dir)
    account = _load_or_create_account(account_path, config_dir)

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


def print_status(config_dir: Path) -> int:
    status = config_status(config_dir)
    print(f"account: {status['account']}")
    print(f"config_dir: {status['config_dir']}")
    print(f"account_file: {status['account_file']}")
    print(f"password_persisted: {status['password_persisted']}")
    return 0


def _load_or_create_account(account_path: Path, config_dir: Path) -> Any:
    from findmy import AppleAccount, LocalAnisetteProvider

    libs_path = _anisette_libs_path(config_dir)
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
        loop = getattr(account, "_evt_loop", None)
        if loop is not None and not loop.is_running():
            loop.run_until_complete(close_result)
        else:
            asyncio.run(close_result)


def _login_state_name(login_state: Any) -> str:
    return str(getattr(login_state, "name", login_state))


def _anisette_libs_path(config_dir: Path) -> Path | None:
    template = os.environ.get(ANISETTE_LIBS_TEMPLATE_ENV)
    if not template:
        return None

    libs_path = config_dir / ANISETTE_LIBS_FILE
    if not libs_path.exists():
        _copy_private_file(Path(template), libs_path)
    return libs_path


def _copy_private_file(source: Path, destination: Path) -> None:
    ensure_config_dir(destination.parent)
    tmp_path = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        shutil.copyfile(source, tmp_path)
        tmp_path.chmod(CONFIG_FILE_MODE)
        os.replace(tmp_path, destination)
        destination.chmod(CONFIG_FILE_MODE)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
