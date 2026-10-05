from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class NativeSelectionSnapshotTests(unittest.TestCase):
    def test_native_model_bounds_identity_merge_and_changes(self):
        compiler = shutil.which('cc')
        if not compiler:
            self.skipTest('C compiler unavailable')
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder) / 'selection-snapshot-test'
            source = Path(__file__).with_name('native_selection_snapshot.c')
            subprocess.run([compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            str(source), '-o', str(executable)], check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)
