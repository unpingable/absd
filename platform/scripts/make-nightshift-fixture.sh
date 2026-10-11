#!/bin/sh
# Produces the frozen Nightshift reference fixture on Linux, with no ABSD
# code involved: the real pinned Nightshift writer runs one observation cycle
# that opens a real AG occurrence through the real pinned `ag-loopctl`, and
# AG itself calls the real Nightshift observation resolver on the store to
# confirm the observation is current. The resulting store bytes, the AG
# requests, and the Linux resolver's answers are written to OUT.
#
#   make-nightshift-fixture.sh OUT
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=${1:?output directory}
. "$root/scripts/inputs.sh"
nightshift_source=$(absd_source NIGHTSHIFT)
ag_source=$(absd_source AG)
nightshift_commit=e2675dd854dbfe633bf14456595d722e88bf92bc
ag_commit=21c8da079f2465a2466c54431cc315699fc57cbe
nightshift_tree=bd7afe042251fc4f007413871589a01d26e0583f
ag_tree=3c44f564e2be9add17224954f6e5bb45ccdec84c
linux_nightshift=$(dirname "$root")/absd-std-nightshift-linux
work=$(dirname "$root")/absd-std-nightshift-fixture-work

test ! -e "$out" || { echo "refusing to overwrite $out" >&2; exit 1; }
rm -rf "$work" "$linux_nightshift"
mkdir -p "$work/ag" "$linux_nightshift" "$work/config" "$work/state" "$work/secrets"
chmod 700 "$work/config" "$work/state" "$work/secrets"
absd_stage_input Nightshift "$nightshift_source" "$nightshift_commit" "$nightshift_tree" "$linux_nightshift"
absd_stage_input AG "$ag_source" "$ag_commit" "$ag_tree" "$work/ag"

(cd "$linux_nightshift" && env -u RUSTFLAGS cargo build --release --locked --offline -p nightshiftd --bin nightshift-observation-resolver)
(cd "$work/ag" && env -u RUSTFLAGS cargo +1.94.0 build --release --locked --offline -p ag-app --bin ag-loopctl)
(cd "$root/tools/nightshift-fixture" && env -u RUSTFLAGS cargo build --release --offline \
    --target x86_64-unknown-linux-gnu --target-dir "$work/driver-target")
resolver=$linux_nightshift/target/release/nightshift-observation-resolver
loopctl=$work/ag/target/release/ag-loopctl
driver=$work/driver-target/x86_64-unknown-linux-gnu/release/nightshift-fixture
store=$work/state/nightshift.sqlite

# AG deployment inputs, shaped as AG's own deployment test seals them
# (crates/ag-app/tests/governed_loop_provisioning.rs): boundary commands for
# the Docket and standing ports, which nothing before authorization invokes,
# and the real Nightshift resolver behind the deployment wrapper AG runs.
cat > "$work/config/boundary-command" <<'SH'
#!/bin/sh
exit 0
SH
chmod 700 "$work/config/boundary-command"
cat > "$work/config/observation-resolver" <<SH
#!/bin/sh
exec "$resolver" --store "$store" --resolver-id nightshift-observation-resolver/v1 --default-ttl-ms 34560000000
SH
chmod 700 "$work/config/observation-resolver"
scope=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["subject"]["scope"]["digest"])' \
    "$linux_nightshift/docs/operator/examples/diagnostic-posture-v1/policy.json")
python3 - "$work/config" "$scope" "$work" <<'PY'
import json, sys
config, scope, work = sys.argv[1], sys.argv[2], sys.argv[3]
jcs = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
open(f"{config}/catalog.json", "wb").write(jcs({
    "schema": "ag.governed-loop.exact-work-catalog/v1",
    "entries": {"example.exact-work/v1": {
        "work_schema": "example.exact-work/v1",
        "subject": "sha256:" + "62" * 32, "scope": scope,
        "precondition": {"required": [], "forbidden": []}}}}))
open(f"{config}/docket-trust.json", "wb").write(jcs({}))
command = f"{config}/boundary-command"
open(f"{config}/enrollment.json", "wb").write(jcs({
    "schema": "ag.governed-loop.runtime-profile-enrollment/v1",
    "profile_label": "absd-nightshift-fixture",
    "observation_resolver": f"{config}/observation-resolver",
    "observation_resolver_id": "nightshift-observation-resolver/v1",
    "standing_resolver": command, "standing_resolver_id": "fixture-standing/v1",
    "max_standing_ttl_ms": 60000,
    "exact_work_catalog": f"{config}/catalog.json", "controlling_review": None,
    "docket": {"schema": "ag.governed-loop.docket-root-enrollment/v1",
               "docket_program": command, "state_directory": f"{work}/state/docket",
               "trust_config": f"{config}/docket-trust.json", "standing_resolver": command,
               "executor_adapter": command, "issuer_principal": "fixture-ag",
               "issuer_key_id": "fixture-key-1", "issuer_key": f"{work}/secrets/issuer.pk8"},
    "human_verifier": None}))
PY
# AG signs with ring, which takes an Ed25519 key as PKCS#8 v2 (seed and
# public key); openssl writes v1, so re-encode its seed and public key.
openssl genpkey -algorithm ed25519 -outform DER -out "$work/secrets/issuer.v1.der"
openssl pkey -inform DER -in "$work/secrets/issuer.v1.der" -pubout -outform DER -out "$work/secrets/issuer.pub.der"
python3 - "$work/secrets" <<'PY'
import sys
d = sys.argv[1]
seed = open(f"{d}/issuer.v1.der", "rb").read()[-32:]
public = open(f"{d}/issuer.pub.der", "rb").read()[-32:]
v2 = (bytes.fromhex("3053020101300506032b657004220420") + seed
      + bytes.fromhex("a123032100") + public)
open(f"{d}/issuer.pk8", "wb").write(v2)
PY
chmod 600 "$work/secrets/issuer.pk8"
"$loopctl" seal-runtime-profile --enrollment "$work/config/enrollment.json" \
    --output "$work/config/runtime-profile.json" > "$work/seal-receipt.json"

# The examples' recurrence evidence is current at 2026-07-27T20:00:10Z, so
# the cycle is evaluated there; AG checks currentness against its own clock,
# so the deployment wrapper it runs carries a 400-day TTL. The frozen
# reference requests below use the resolver test's 10-minute TTL instead.
due=2026-07-27T20:00:00Z
"$driver" --examples "$linux_nightshift/docs/operator/examples/diagnostic-posture-v1" \
    --due "$due" --request-out "$work/cycle-request.json" \
    --support-resolver "$linux_nightshift/qualification/operational/fixtures/pulse-support-resolver" \
    --ag-loopctl "$loopctl" --ag-database "$work/state/ag.sqlite" \
    --ag-observation-resolver "$work/config/observation-resolver" \
    --ag-runtime-profile "$work/config/runtime-profile.json" \
    --store "$store" > "$work/cycle.json"

mkdir -p "$out/store"
for file in "$work/state"/nightshift.sqlite*; do
    cp "$file" "$out/store/"
done
cp "$work/cycle-request.json" "$work/cycle.json" "$out/"
"$loopctl" status --database "$work/state/ag.sqlite" > "$out/ag-status.json"
python3 "$root/scripts/nightshift_reference.py" record \
    --resolver "$resolver" --fixture "$out" --nightshift-commit "$nightshift_commit" \
    --ag-commit "$ag_commit" --due "$due"
rm -rf "$work" "$linux_nightshift"
printf '%s\n' "NIGHTSHIFT FIXTURE CREATED $out"
