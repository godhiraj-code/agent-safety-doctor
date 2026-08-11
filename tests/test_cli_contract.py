import json
import subprocess
import sys
from pathlib import Path


def run_cli(*args: str, cwd: Path | None = None):
    return subprocess.run(
        [sys.executable, "-m", "agent_safety_doctor.cli", *args],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_cli_writes_json_and_infers_format(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".env").write_text("API_KEY=livecredentialvalue123456789\n", encoding="utf-8")
    output = tmp_path / "report.json"

    proc = run_cli("scan", str(tmp_path), "--output", str(output))

    assert proc.returncode == 0, proc.stderr
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0"
    assert data["score"] < 100


def test_cli_stdout_markdown(tmp_path: Path):
    (tmp_path / ".git").mkdir()

    proc = run_cli("scan", str(tmp_path), "--output", "-")

    assert proc.returncode == 0
    assert "Agent Safety Doctor Report" in proc.stdout


def test_cli_fail_under_returns_nonzero(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "deploy.sh").write_text("terraform destroy -auto-approve\n", encoding="utf-8")

    proc = run_cli("scan", str(tmp_path), "--output", str(tmp_path / "report.md"), "--fail-under", "100")

    assert proc.returncode == 3
    assert "below fail-under threshold" in proc.stderr


def test_cli_invalid_path_returns_usage_error(tmp_path: Path):
    proc = run_cli("scan", str(tmp_path / "missing"))

    assert proc.returncode == 2
    assert "Workspace path must be an existing directory" in proc.stderr


def test_cli_writes_html_by_extension(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "deploy.sh").write_text("kubectl delete namespace prod\n", encoding="utf-8")
    output = tmp_path / "report.html"

    proc = run_cli("scan", str(tmp_path), "--output", str(output))

    assert proc.returncode == 0, proc.stderr
    html = output.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "kubectl delete" in html


def test_cli_stdout_json_with_summary_keeps_stdout_parseable(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "deploy.sh").write_text("kubectl delete namespace prod\n", encoding="utf-8")

    proc = run_cli("scan", str(tmp_path), "--output", "-", "--format", "json", "--summary")

    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["counts"]["total"] >= 1
    assert "score=" in proc.stderr


def test_cli_rejects_invalid_config_types(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    config = tmp_path / "bad.toml"
    config.write_text("[scanner]\nignore_globs = 'not-a-list'\n", encoding="utf-8")

    proc = run_cli("scan", str(tmp_path), "--config", str(config))

    assert proc.returncode == 2
    assert "scanner.ignore_globs must be a list of strings" in proc.stderr
