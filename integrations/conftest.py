# Run pytest from this directory (integrations/). The plugin directory name
# ``hermes-native`` contains a hyphen, which is a legal directory for Hermes'
# path-based loader but not a legal Python module name. pytest must not treat
# it as a package, so we ignore its __init__.py entirely; the test loads the
# plugin via importlib from the file path.
collect_ignore = ["hermes-native"]
