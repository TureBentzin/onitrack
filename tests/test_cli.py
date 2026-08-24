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


def test_people_requires_subcommand_uses_people_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["people"])

    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "usage: onitrack people" in error
    assert "{list}" in error
    assert "people requires a subcommand" in error
