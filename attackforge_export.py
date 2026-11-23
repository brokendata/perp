"""Optional local AttackForge review bundles; publishing is handled by the skill."""
import importlib.util
from pathlib import Path


def load_bundle_helper():
    source = Path(__file__).resolve().parent/'skills/perp-attackforge/scripts/bundle.py'
    if not source.is_file():
        raise ValueError('AttackForge export requires the bundled skills/perp-attackforge directory')
    spec = importlib.util.spec_from_file_location('perp_attackforge_bundle', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_attackforge_bundle(results, account_context=None, evidence=()):
    helper = load_bundle_helper()
    output = helper.build_bundle(results, account_context, evidence)
    helper.verify_bundle(output)
    return output
