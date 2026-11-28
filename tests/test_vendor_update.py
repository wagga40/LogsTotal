"""Vendor downloads must not replace a working bundle with a bad response."""

from __future__ import annotations

import shlex
import shutil
import subprocess

import pytest
from _taskfile import all_tasks


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
@pytest.mark.parametrize("response", ["valid", "not-the-browser-build", "download-failure"])
def test_vendor_download_preserves_bundle_on_failure(tmp_path, response):
    vendor_dir = tmp_path / "app/static/vendor"
    vendor_dir.mkdir(parents=True)
    bundle = vendor_dir / "tailwind.js"
    original = 'document.querySelectorAll(`style[type="text/tailwindcss"]`);\n'
    bundle.write_text(original)

    # file:// exercises the real curl command without a network dependency.
    source = tmp_path / "response.js"
    if response == "valid":
        source.write_text('document.querySelectorAll(`style[type="text/tailwindcss"]`); // updated\n')
    elif response == "not-the-browser-build":
        # Tailwind 3's Play CDN bundle reads a JS config and no text/tailwindcss block, so
        # every page would render unstyled with it — and the download itself succeeds.
        source.write_text("window.tailwind = {config: {}};\n")

    download = next(cmd["cmd"] for cmd in all_tasks()["vendor:update"]["cmds"] if isinstance(cmd, dict) and "for" in cmd)
    command = download.replace("{{.ASSET}}", shlex.join(["tailwind.js", source.as_uri()]))
    result = subprocess.run(["bash", "-c", command], cwd=tmp_path, capture_output=True, text=True)

    if response == "valid":
        assert result.returncode == 0, result.stdout + result.stderr
        assert bundle.read_text() == source.read_text()
    else:
        assert result.returncode != 0, "the updater accepted a failed download"
        assert bundle.read_text() == original
    assert sorted(path.name for path in vendor_dir.iterdir()) == ["tailwind.js"]
