import argparse
import sys
import unittest
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
root = parser.parse_args().root.resolve()
sys.path.insert(0, str(root))
suite = unittest.defaultTestLoader.discover(str(root / "tests"))
result = unittest.TestResult()
suite.run(result)
for case, error in result.failures + result.errors:
    print("FAIL", case.id())
    lines = error.splitlines()
    print("\n".join(line[:300] for line in lines[-3:]))
print("tests=%d failures=%d errors=%d skipped=%d" % (
    result.testsRun, len(result.failures), len(result.errors), len(result.skipped)))
sys.exit(not result.wasSuccessful())
