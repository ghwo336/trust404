"""CI workflow shape for the published amd64 detector image."""

from __future__ import annotations

import re

import yaml

from tests.detector.conftest import REPO_ROOT

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "detector-image.yml"
USES_RE = re.compile(r"^(actions|docker)/[a-z-]+@v\d+$")


def _walk_uses(node: object) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        uses = node.get("uses")
        if isinstance(uses, str):
            found.append(uses)
        for value in node.values():
            found.extend(_walk_uses(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_uses(item))
    return found


def _run_scripts(node: object) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        run = node.get("run")
        if isinstance(run, str):
            found.append(run)
        for value in node.values():
            found.extend(_run_scripts(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_run_scripts(item))
    return found


def test_detector_image_workflow_shape() -> None:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert data["permissions"] == {"contents": "write", "packages": "write"}
    on = data["on"]
    assert "workflow_dispatch" in on
    tags = on["push"]["tags"]
    assert "submission-*" in tags
    jobs = data["jobs"]
    assert len(jobs) == 1
    job = next(iter(jobs.values()))
    assert job["runs-on"] == "ubuntu-latest"
    for uses in _walk_uses(data):
        assert USES_RE.match(uses), uses
    for script in _run_scripts(data):
        assert "ghp_" not in script
        assert "ghs_" not in script
        assert "github_pat_" not in script
    joined = "\n".join(_run_scripts(data))
    assert "--network none" in joined
