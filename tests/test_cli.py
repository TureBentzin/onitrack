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


def test_people_requires_subcommand_uses_people_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people" in error
    assert "{list,alias,location}" in error
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
