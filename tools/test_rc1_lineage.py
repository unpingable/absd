"""The public release CLI takes lineage only from explicit inputs."""
import contextlib
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'platform/scripts'))
import release_manifest


class ExplicitLineage(unittest.TestCase):
    def check_choice(self, environment, arguments, expected):
        with patch.dict(os.environ, environment, clear=True), patch.object(release_manifest, 'build') as build:
            with contextlib.redirect_stdout(io.StringIO()):
                result = release_manifest.main(['build', '--kernel', '/fixture/kernel',
                                                '--platform', '/fixture/platform', *arguments, '/fixture/release'])
        self.assertEqual(result, 0)
        self.assertEqual(build.call_args.args[6], expected)

    def test_unset_lineage_does_not_search_a_sibling(self):
        self.check_choice({}, [], None)

    def test_environment_names_lineage(self):
        self.check_choice({'ABSD_COMPONENTS_TOML': '/fixture/lineage.toml'}, [], '/fixture/lineage.toml')

    def test_explicit_argument_overrides_environment(self):
        self.check_choice({'ABSD_COMPONENTS_TOML': '/fixture/stale.toml'},
                          ['--components', '/fixture/chosen.toml'], '/fixture/chosen.toml')


if __name__ == '__main__':
    unittest.main()
