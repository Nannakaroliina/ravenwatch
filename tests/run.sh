#!/bin/sh
# Run every ravenwatch test suite. Each suite builds throwaway repositories in $TMPDIR and only
# pushes to throwaway bare remotes there. Exits non-zero if any check fails.
dir=$(cd "$(dirname "$0")" && pwd)
status=0
for t in "$dir"/gate_*.sh "$dir"/round*.sh; do
  sh "$t" || status=1
done
[ "$status" -eq 0 ] && echo "all suites passed" || echo "SOME CHECKS FAILED"
exit $status
