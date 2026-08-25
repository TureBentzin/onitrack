import pytest

from onitrack import __version__
from onitrack.main import main


def test_version_command(capsys):
    assert main(["version"]) == 0

    captured = capsys.readouterr()
    assert captured.out.strip() == __version__


def test_doctor_command(capsys):
    assert main(["doctor"]) == 0

    captured = capsys.readouterr()
    assert captured.out.strip() == "onitrack base environment available"


def test_auth_provision_accepts_refresh_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["auth", "provision", "--help"])

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--refresh" in output
    assert "--validation-json" in output


def test_people_list_requires_output_mode(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people", "list"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people list" in error
    assert "choose --anonomyse or --plain" in error


def test_people_list_rejects_two_output_modes(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people", "list", "--anonomyse", "--plain"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people list" in error
    assert "choose only one of --anonomyse or --plain" in error


def test_people_location_get_requires_output_mode(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people", "location", "get", "--alias", "home"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people location get" in error
    assert "choose --anonomyse or --plain" in error


def test_people_location_get_rejects_two_output_modes(capsys):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "people",
                "location",
                "get",
                "--alias",
                "home",
                "--anonomyse",
                "--plain",
            ],
        )

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people location get" in error
    assert "choose only one of --anonomyse or --plain" in error


def test_people_key_import_requires_anonymized_mode(capsys):
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "people",
                "key",
                "import",
                "--person-id",
                "a" * 64,
                "--advertised-id",
                "advertised",
            ],
        )

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people key import" in error
    assert "choose --anonomyse" in error


def test_people_key_acquire_requires_anonymized_mode(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people", "key", "acquire", "--alias", "home"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people key acquire" in error
    assert "choose --anonomyse" in error


def test_people_key_acquire_exposes_wait_and_redacted_debug_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people", "key", "acquire", "--help"])

    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--wait-seconds" in output
    assert "--debug-redacted" in output
    assert "--anonomyse" in output


def test_people_requires_subcommand_uses_people_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people" in error
    assert "{list,alias,key,location}" in error
    assert "people requires a subcommand" in error


def test_people_alias_requires_subcommand_uses_alias_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people", "alias"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people alias" in error
    assert "{set,setup}" in error
    assert "people alias requires a subcommand" in error


def test_people_location_requires_subcommand_uses_location_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people", "location"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people location" in error
    assert "{get}" in error
    assert "people location requires a subcommand" in error
