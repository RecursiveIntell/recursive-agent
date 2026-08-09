"""Task 4.3 — packaging/install round-trip in an isolated HERMES_HOME.

Installs the plugin into a temporary home via install-hermes-plugin.sh, asserts
the manifest and files exist, then uninstalls and asserts the home is clean.
"""

import os
import subprocess

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
INSTALL = os.path.join(REPO_ROOT, "scripts", "install-hermes-plugin.sh")
UNINSTALL = os.path.join(REPO_ROOT, "scripts", "uninstall-hermes-plugin.sh")


def _run(script, env):
    return subprocess.run([script], env=env, capture_output=True, text=True)


def test_install_uninstall_round_trip(tmp_path):
    # A temp HERMES_HOME that shares the active user for socket/fs checks.
    home = tmp_path / "hermes_home"
    home.mkdir()
    env = {**os.environ, "HERMES_HOME": str(home)}

    install = _run(INSTALL, env)
    assert install.returncode == 0, install.stderr

    plugin_dir = home / "plugins" / "recursive-agent-native"
    manifest = home / "plugins" / "recursive-agent-native.manifest"
    assert plugin_dir.exists()
    assert manifest.exists()
    assert (plugin_dir / "plugin.yaml").exists()
    assert (plugin_dir / "__init__.py").exists()
    assert not (plugin_dir / "tests").exists(), "tests must not ship into installs"

    uninstall = _run(UNINSTALL, env)
    assert uninstall.returncode == 0, uninstall.stderr
    assert not plugin_dir.exists()
    assert not manifest.exists()
