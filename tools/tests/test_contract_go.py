# SPDX-License-Identifier: BSD-3-Clause
"""Check wrapper isolation with a fake executable, without invoking a Go SDK."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2]


class ContractGoTests(unittest.TestCase):
    def test_isolation_precedes_first_go_invocation(self):
        with tempfile.TemporaryDirectory(prefix="contract-go-") as temporary:
            root = Path(temporary).resolve()
            (root / "tools").mkdir()
            (root / ".tools/go/bin").mkdir(parents=True)
            shutil.copy2(SOURCE / "tools/run-contract-go.sh", root / "tools")
            (root / ".go-version").write_text("1.27.2\n")
            fake = root / ".tools/go/bin/go"
            fake.write_text("""#!/bin/sh
set -eu
[ "$GOTOOLCHAIN" = local ]
[ "$GOENV" = off ]
[ "$GOWORK" = off ]
[ "$GOMAXPROCS" = 2 ]
[ "$GOFLAGS" = -mod=readonly ]
[ "$GOPROXY" = off ]
[ "$GOSUMDB" = off ]
[ "$GOCACHE" = "$FIXTURE_ROOT/.tools/contract-go-cache" ]
[ "$GOMODCACHE" = "$FIXTURE_ROOT/.tools/contract-mod-cache" ]
if [ "$#" = 2 ] && [ "$1" = env ] && [ "$2" = GOVERSION ]; then
    echo version >> "$FIXTURE_ROOT/calls"
    echo go1.27.2
elif [ "$#" = 2 ] && [ "$1" = test ] && [ "$2" = ./... ]; then
    echo test >> "$FIXTURE_ROOT/calls"
else
    exit 9
fi
""")
            fake.chmod(0o755)
            hostile = dict(os.environ, FIXTURE_ROOT=str(root),
                           GOTOOLCHAIN="go9.9.9+auto", GOENV="/not/read/goenv",
                           GOWORK="/not/read/go.work", GOMAXPROCS="99",
                           GOFLAGS="-mod=mod", GOPROXY="https://unused.invalid",
                           GOSUMDB="unused.invalid", GOCACHE="/not/write/cache",
                           GOMODCACHE="/not/write/modules")
            result = subprocess.run(["sh", "tools/run-contract-go.sh", "test", "./..."],
                                    cwd=root, env=hostile, capture_output=True, text=True,
                                    timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((root / "calls").read_text(), "version\ntest\n")


if __name__ == "__main__":
    unittest.main()
