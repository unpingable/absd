#!/bin/sh
set -e
G=${ABSD_COMPOSITION_RUN_ROOT:?fresh occurrence root required}
P=$G/logs/pipeline.log
echo "SHOULD matrix start $(date -u +%FT%TZ)" >> $P
$G/tools/cases.sh p0 p0c p0n r4a r2a r2b r2c r3a r3b r3c r1a r1b r4b r4d r4f l4 l5 l6 l7 b2 b3 b4 b5 b6 b7 l3 s2
echo "SHOULD regress start $(date -u +%FT%TZ)" >> $P
$G/tools/regress.sh matrix corefsd upgrade ghost-ata ghost-nvme served survival link
echo "SHOULD subset done; full composition requires sealed intake $(date -u +%FT%TZ)" >> $P
