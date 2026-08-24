import os
import sys

import pytest


@pytest.fixture(autouse=True)
def fake_age_tools(monkeypatch, tmp_path):
    bin_dir = tmp_path / "age-bin"
    bin_dir.mkdir()
    age = bin_dir / "age"
    age_keygen = bin_dir / "age-keygen"

    age.write_text(
        f"""#!{sys.executable}
import base64
import sys

payload = sys.stdin.buffer.read()
if "--decrypt" in sys.argv:
    prefix = b"AGEFAKE\\n"
    if not payload.startswith(prefix):
        sys.stderr.write("invalid fake age payload\\n")
        sys.exit(1)
    sys.stdout.buffer.write(base64.b64decode(payload[len(prefix):]))
else:
    sys.stdout.buffer.write(b"AGEFAKE\\n")
    sys.stdout.buffer.write(base64.b64encode(payload))
""",
        encoding="utf-8",
    )
    age_keygen.write_text(
        f"""#!{sys.executable}
print("# created: 2026-08-24T00:00:00Z")
print("# public key: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
print("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
""",
        encoding="utf-8",
    )
    age.chmod(0o755)
    age_keygen.chmod(0o755)

    old_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{old_path}")
