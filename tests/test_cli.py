from pathlib import Path

from agent_safety_doctor.cli import render_report, safety_score
from agent_safety_doctor.config import load_config
from agent_safety_doctor.report import render_html, render_json, render_markdown
from agent_safety_doctor.scanner import scan_workspace


def test_detects_secret_file_and_risky_command(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".env").write_text("API_KEY=livecredentialvalue123456789\n", encoding="utf-8")
    (tmp_path / "deploy.sh").write_text("rm -rf /important/data\n", encoding="utf-8")

    result = scan_workspace(tmp_path)
    categories = {f.category for f in result.findings}

    assert "secrets_exposure" in categories
    assert "secret_value_pattern" in categories
    assert "destructive_action" in categories
    assert result.score < 100


def test_secret_values_are_redacted_from_reports(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    secret_value = "super-sensitive-token-123456"
    (tmp_path / "settings.env").write_text(f"SERVICE_TOKEN={secret_value}\n", encoding="utf-8")

    result = scan_workspace(tmp_path)
    markdown = render_markdown(result)
    json_report = render_json(result)

    assert "SERVICE_TOKEN=[REDACTED]" in markdown
    assert secret_value not in markdown
    assert secret_value not in json_report


def test_quoted_secret_with_spaces_is_redacted_from_all_report_formats(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    secret_value = "live secret value with spaces 123456"
    (tmp_path / "deploy.sh").write_text(
        f'rm -rf /important/data; SERVICE_TOKEN="{secret_value}"\n',
        encoding="utf-8",
    )

    result = scan_workspace(tmp_path)
    reports = [render_markdown(result), render_json(result), render_html(result)]

    assert "secret_value_pattern" in {finding.category for finding in result.findings}
    assert "destructive_action" in {finding.category for finding in result.findings}
    assert all(secret_value not in report for report in reports)
    assert all("SERVICE_TOKEN=[REDACTED]" in report for report in reports)


def test_quoted_secret_values_are_detected_and_redacted(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    secret_value = "livecredentialvalue123456789"
    (tmp_path / "settings.py").write_text(f'API_TOKEN="{secret_value}"\n', encoding="utf-8")

    result = scan_workspace(tmp_path)
    markdown = render_markdown(result)

    assert "secret_value_pattern" in {finding.category for finding in result.findings}
    assert secret_value not in markdown
    assert "API_TOKEN=[REDACTED]" in markdown


def test_inline_command_tokens_are_redacted_from_evidence(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    secret_value = "livecredentialvalue123456789"
    (tmp_path / "deploy.sh").write_text(f"rm -rf /tmp/x --token {secret_value}\n", encoding="utf-8")

    result = scan_workspace(tmp_path)
    markdown = render_markdown(result)
    json_report = render_json(result)

    assert "destructive_action" in {finding.category for finding in result.findings}
    assert secret_value not in markdown
    assert secret_value not in json_report
    assert "--token [REDACTED]" in markdown


def test_private_key_blocks_are_detected_without_leaking_body(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    key_body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
    begin = "-----BEGIN " + "PRIVATE KEY" + "-----"
    end = "-----END " + "PRIVATE KEY" + "-----"
    (tmp_path / "private.pem").write_text(f"{begin}\\n{key_body}\\n{end}\\n", encoding="utf-8")

    result = scan_workspace(tmp_path)
    report = render_json(result)

    assert "secret_value_pattern" in {finding.category for finding in result.findings}
    assert key_body not in report


def test_detects_mcp_surface_and_missing_docs(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "mcp.json").write_text('{"mcpServers":{"ops":{"tools":["delete","write"]}}}', encoding="utf-8")

    result = scan_workspace(tmp_path)
    categories = {f.category for f in result.findings}

    assert "mcp_tool_surface" in categories
    assert "mcp_server_risk" in categories
    assert "mcp_detected" in categories
    assert "missing_policy" in categories
    assert "missing_rollback" in categories


def test_report_contains_postmortem_and_policy(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    result = scan_workspace(tmp_path)
    report = render_report(tmp_path, result)

    assert "Agent Safety Doctor Report" in report
    assert "Approval policy starter" in report
    assert "Incident postmortem template" in report
    assert "Scan metadata" in report


def test_config_can_ignore_paths_and_allow_example_secret_files(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "ignored.env").write_text("API_KEY=livecredentialvalue123456789\n", encoding="utf-8")
    (tmp_path / "safe.env.example").write_text("API_KEY=example\n", encoding="utf-8")
    config_path = tmp_path / ".agent-safety-doctor.toml"
    config_path.write_text(
        "[scanner]\nignore_globs = ['ignored.env']\nallow_secret_file_globs = ['*.example']\n",
        encoding="utf-8",
    )

    config = load_config(tmp_path)
    result = scan_workspace(tmp_path, config)

    paths = {finding.path for finding in result.findings}
    assert "ignored.env" not in paths
    assert "safe.env.example" not in paths
    assert "node_modules" in config.ignore_dirs


def test_policy_negations_do_not_count_as_policy(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "README.md").write_text("There is no approval policy and no rollback process.\n", encoding="utf-8")

    result = scan_workspace(tmp_path)
    categories = {finding.category for finding in result.findings}

    assert "missing_policy" in categories
    assert "missing_rollback" in categories


def test_policy_questions_do_not_count_as_positive_evidence(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "README.md").write_text(
        "Do we have an approval policy?\nWhere is the rollback process?\n",
        encoding="utf-8",
    )

    categories = {finding.category for finding in scan_workspace(tmp_path).findings}

    assert "missing_policy" in categories
    assert "missing_rollback" in categories


def test_detects_additional_destructive_commands(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "ops.sh").write_text(
        "git push origin main --force\naws s3 rb s3://prod --force\nchmod 777 /prod\n",
        encoding="utf-8",
    )

    result = scan_workspace(tmp_path)
    evidence = "\n".join(f.evidence or "" for f in result.findings)

    assert "git push origin main --force" in evidence
    assert "aws s3 rb s3://prod --force" in evidence
    assert "chmod 777 /prod" in evidence


def test_symlinked_files_are_skipped(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    outside = tmp_path.parent / "outside-secret.env"
    outside.write_text("API_KEY=livecredentialvalue123456789\n", encoding="utf-8")
    link = tmp_path / "linked-secret.env"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        return

    result = scan_workspace(tmp_path)

    assert "linked-secret.env" not in {finding.path for finding in result.findings}
    assert result.metadata.files_skipped >= 1


def test_json_report_is_machine_readable(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    result = scan_workspace(tmp_path)
    data = render_json(result)

    assert '"schema_version": "1.0"' in data
    assert '"score"' in data
    assert '"findings"' in data


def test_backward_compatible_safety_score_accepts_findings(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".env").write_text("API_KEY=livecredentialvalue123456789\n", encoding="utf-8")
    result = scan_workspace(tmp_path)

    assert safety_score(result.findings) == result.score


def test_does_not_flag_scanner_config_constants_as_secret_values(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "config.py").write_text(
        'SECRET_NAME_RE = re.compile("token")\nallow_secret_file_globs=("*.example",)\n',
        encoding="utf-8",
    )

    result = scan_workspace(tmp_path)

    assert "secret_value_pattern" not in {finding.category for finding in result.findings}


def test_placeholder_matching_does_not_hide_secret_with_test_substring(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    secret_value = "attestationcredentialvalue123456789"
    (tmp_path / "settings.env").write_text(f"SERVICE_TOKEN={secret_value}\n", encoding="utf-8")

    result = scan_workspace(tmp_path)

    assert "secret_value_pattern" in {finding.category for finding in result.findings}
    assert secret_value not in render_json(result)


def test_display_root_hides_absolute_config_path(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    config_path = tmp_path / ".agent-safety-doctor.toml"
    config_path.write_text("[scanner]\n", encoding="utf-8")

    result = scan_workspace(tmp_path, load_config(tmp_path), display_root="safe-demo")
    report = render_json(result)

    assert str(tmp_path) not in report
    assert result.metadata.root == "safe-demo"
    assert result.metadata.config_path == ".agent-safety-doctor.toml"


def test_html_report_is_escaped_and_designed(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "deploy.sh").write_text("rm -rf /important/<prod>\n", encoding="utf-8")

    html = render_html(scan_workspace(tmp_path))

    assert "<!doctype html>" in html
    assert "Agent Safety Doctor" in html
    assert "&lt;prod&gt;" in html
    assert "rm -rf /important/<prod>" not in html
