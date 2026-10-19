#!/usr/bin/env python3
"""Generate public inputs for the bounded real-verifier countertrace, after admission.

Never invoked by a build or test. Private fixture keys are outside source/evidence.
The existing TLS PKI recipe and canonical qualification predicates are unchanged.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

ANCHOR = 1767268800
FUTURE = 2082801600


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def seal(path, value):
    with path.open("x") as out:
        json.dump(value, out, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    args = parser.parse_args()
    admission = json.loads(args.admission.read_text())
    script = Path(__file__).resolve()
    if (admission.get("pki_generation_go") is not True
            or admission.get("script_sha256") != sha(script)
            or admission.get("host_name") != socket.gethostname()
            or not admission.get("owner") or not admission.get("run")):
        raise SystemExit("exact isolated-host fixture admission required")
    source = Path(admission["source_root"]).resolve()
    public = Path(admission["public_dir"]).resolve()
    private = Path(admission["private_dir"]).resolve()
    if (public.exists() or private.exists() or public == private
            or public in private.parents or private in public.parents
            or source in public.parents or source in private.parents
            or public == source or private == source
            or not source.is_dir() or not (source / ".git").exists()):
        raise SystemExit("fresh disjoint public/private directories outside source required")
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != admission.get("source_revision"):
        raise SystemExit("source revision differs from admission")
    os.umask(0o077)
    public.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    lifecycle = {"schema_version": 1, "run": admission["run"], "owner": admission["owner"],
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "purpose": "Offline standard-verifier SNTP/TLS non-influence countertrace only",
        "private_dir": str(private), "private_keys": ["root.key", "leaf.key"],
        "private_material_in_evidence": False,
        "retirement": "Exact private keys/bootstrap/database/config are disposable immediately after public certificate/control seal; no live TLS server/replay needs them. Execution owner removes them after checking OpenSSL has exited, and records disposition. On failure, same owner reconciles exact created files, then retires them.",
        "next_review": admission["next_review"]}
    seal(public / "PRIVATE-LIFECYCLE.json", lifecycle)
    commands = []

    def run(arguments, expected=0):
        result = subprocess.run(["/usr/bin/openssl", *arguments], capture_output=True, text=True, timeout=30)
        commands.append({"argv": ["/usr/bin/openssl", *arguments], "exit": result.returncode})
        if result.returncode != expected:
            raise RuntimeError("OpenSSL fixture command failed: " + arguments[0])
        return result

    try:
        for name in ["root", "leaf"]:
            run(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(private / (name + ".key"))])
        (private / "newcerts").mkdir(mode=0o700)
        (private / "index").write_text("")
        (private / "serial").write_text("1000\n")
        bootstrap = private / "bootstrap.pem"
        run(["req", "-new", "-x509", "-sha256", "-days", "1", "-key", str(private / "root.key"),
             "-subj", "/CN=ABSD SNTP Time Fixture Root", "-out", str(bootstrap),
             "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-addext", "subjectKeyIdentifier=hash"])
        config = private / "ca.cnf"

        def configure(certificate):
            config.write_text("[ca]\ndefault_ca=fixture\n[fixture]\ndatabase=" + str(private / "index")
                + "\nnew_certs_dir=" + str(private / "newcerts") + "\nserial=" + str(private / "serial")
                + "\nprivate_key=" + str(private / "root.key") + "\ncertificate=" + str(certificate)
                + "\ndefault_md=sha256\ndefault_days=1\nunique_subject=no\npolicy=subject\n[subject]\ncommonName=supplied\n"
                  "[ca_ext]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
                  "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                  "subjectAltName=DNS:absd-fixture.test\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        configure(bootstrap)
        run(["req", "-new", "-sha256", "-key", str(private / "root.key"), "-subj", "/CN=ABSD SNTP Time Fixture Root", "-out", str(public / "root.csr")])
        run(["ca", "-batch", "-selfsign", "-notext", "-config", str(config), "-extensions", "ca_ext", "-in", str(public / "root.csr"),
             "-out", str(public / "root.pem"), "-startdate", "20250101000000Z", "-enddate", "20370101000000Z"])
        configure(public / "root.pem")
        run(["req", "-new", "-sha256", "-key", str(private / "leaf.key"), "-subj", "/CN=absd-fixture.test", "-out", str(public / "leaf.csr")])
        for year in [2026, 2036]:
            run(["ca", "-batch", "-notext", "-config", str(config), "-extensions", "leaf", "-in", str(public / "leaf.csr"),
                 "-out", str(public / f"leaf-{year}.pem"), "-startdate", f"{year}0101000000Z", "-enddate", f"{year}0102000000Z"])
        for name in ["root", "leaf-2026", "leaf-2036"]:
            run(["x509", "-in", str(public / (name + ".pem")), "-outform", "DER", "-out", str(public / (name + ".der"))])
        controls = []
        for leaf, at, good in [(2026, ANCHOR, True), (2036, ANCHOR, False), (2036, FUTURE, True)]:
            command = ["verify", "-CAfile", str(public / "root.pem"), "-no-CApath", "-no-CAstore", "-attime", str(at),
                       "-purpose", "sslserver", "-verify_hostname", "absd-fixture.test", str(public / f"leaf-{leaf}.pem")]
            result = run(command, 0 if good else 2)
            if not good and "error 9 at 0 depth lookup" not in result.stderr:
                raise RuntimeError("future control did not fail as NOT_YET_VALID")
            controls.append({"leaf": leaf, "at": at, "disposition": "PASS" if good else "EXPECTED_NOT_YET_VALID", "stdout": result.stdout, "stderr": result.stderr})
        seal(public / "PUBLIC-TIME-CERTIFICATES.json", {"schema_version": 1, "run": admission["run"], "source_revision": revision,
            "script_sha256": sha(script), "openssl_sha256": sha("/usr/bin/openssl"), "openssl_version": run(["version", "-a"]).stdout,
            "anchor_2026": ANCHOR, "future_2036": FUTURE, "commands": commands, "controls": controls,
            "public_files": [{"name": p.name, "sha256": sha(p)} for p in sorted(public.iterdir()) if p.is_file()],
            "private_material_in_evidence": False, "private_retirement_owner": admission["owner"]})
    except BaseException as error:
        seal(public / "FAIL.json", {"run": admission["run"], "error_type": type(error).__name__, "message": str(error),
             "commands": commands, "private_retirement_owner": admission["owner"], "disposition": "FAIL"})
        raise


if __name__ == "__main__":
    main()
