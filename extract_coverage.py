#!/usr/bin/env python

import json
import sys

if len(sys.argv) != 2:
	print("Usage: {} frameworkname".format(sys.argv[0]), file = sys.stderr)
	exit(1)

framework = sys.argv[1]

j = json.load(sys.stdin)
for i in range(len(j["targets"])):
	if j["targets"][i]["name"] == framework:
		print("{0:.0f}".format(j["targets"][i]["lineCoverage"] * 100))
		exit(0)

exit(1)
