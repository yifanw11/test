#!/usr/bin/env python

import re
import subprocess
import sys
import os

# -MG ignores missing files, which we remove later on
deps = subprocess.check_output("gcc".split() + ["-x", "c", "-MM", "-MG", sys.argv[1]])
deps = re.sub(r'\w+\.o: ', '', deps)
deps = deps.replace('\\', '')
deps = deps.split()
deps = [f for f in deps if os.path.exists(f)]
deps = " ".join(deps)
print deps,
