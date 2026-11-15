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


def test_installed_v2_client_is_usable_without_the_source_checkout(tmp_path):
    import sys

    home = tmp_path / "isolated_native_home"
    home.mkdir()
    env = {"PATH": os.environ["PATH"], "HOME": str(home),
           "HERMES_HOME": str(home), "LANG": "C.UTF-8"}
    installed = _run(INSTALL, env)
    assert installed.returncode == 0, installed.stderr
    plugin_dir = home / "plugins" / "recursive-agent-native"
    probe = '''
import importlib, importlib.util, inspect, pathlib, sys
root = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("installed_native", root / "__init__.py", submodule_search_locations=[str(root)])
package = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = package
spec.loader.exec_module(package)
client = importlib.import_module("installed_native.governed_client")
assert pathlib.Path(inspect.getfile(client.NativeGovernanceClient)).resolve().parent == root.resolve()
rpc = client.NativeGovernanceClient(str(root / "absent.sock"))
try:
    rpc.attempt_readback("v1:recursive-agent/run/v1:det:" + "a" * 64, "intent:installed-fixture")
except client.DaemonGovernanceError as error:
    assert error.code == "DAEMON_UNREACHABLE"
else:
    raise AssertionError("missing daemon did not fail closed")
print("installed-v2-client-exercised")
'''
    checked = subprocess.run([sys.executable, "-I", "-B", "-c", probe, str(plugin_dir)],
                             cwd=home, env=env, capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    assert checked.stdout.strip() == "installed-v2-client-exercised"
    assert not (plugin_dir / "tests").exists()
    assert not (plugin_dir / "__pycache__").exists()
    uninstalled = _run(UNINSTALL, env)
    assert uninstalled.returncode == 0, uninstalled.stderr
    assert not plugin_dir.exists()


def test_dangling_plugin_directory_is_refused_without_following_it(tmp_path):
    home = tmp_path / "home"
    plugins = home / "plugins"
    plugins.mkdir(parents=True)
    target = tmp_path / "must_not_be_created"
    link = plugins / "recursive-agent-native"
    link.symlink_to(target, target_is_directory=True)
    result = _run(INSTALL, {**os.environ, "HERMES_HOME": str(home)})
    assert result.returncode != 0
    assert link.is_symlink()
    assert not target.exists()
