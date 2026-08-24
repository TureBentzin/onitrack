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
