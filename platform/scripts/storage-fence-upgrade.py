#!/usr/bin/env python3
"""Real RC1 service history followed by copy-only guard conversion.

Only a fresh local fixture omits the seed. The supplied legacy executables
use default release dev. An interrupted boot must refuse conversion; a
later successful halt may convert without resetting the charged history.
"""
import argparse
import importlib.util
import json
import shutil
from pathlib import Path
import sys
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import storage_fence_guest as guest
import storage_fence_state as guard
import storage_fence_upgrade as upgrade


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('platform','kernel','key','work','legacy-fsd','legacy-sshd'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    args.qemu='qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand'
    args.sshd_controls=args.legacy_sshd
    work=Path(args.work).resolve();work.mkdir(parents=True,exist_ok=False,mode=0o700)
    matrix,release=load('storage-fence-matrix.py'),load('release.py')
    key=Path(args.key).resolve()
    with patch.object(guard,'fresh_files',return_value=[]):
        target=matrix.new_target(args,work,key,None)
    target.fsd_elf=Path(args.legacy_fsd).resolve()
    result={'legacy_fsd_sha256':upgrade.digest(args.legacy_fsd),
            'legacy_sshd_sha256':upgrade.digest(args.legacy_sshd),
            'scope':'Retained RC1 services under current kernel; no frozen RC1 kernel claim.'}
    try:
        matrix.start(target,'ata')
        target.stop()
        original=upgrade.digest(target.image)
        try:
            upgrade.convert(target.image,work/'bad.img',target.serial(),work/'bad-work',target.kernel,
                            oi=release.oi,release=release,attest_no_writes_since_halt=True,
                            halt_image_sha256=original)
        except ValueError as error:result['unclean_refusal']=str(error)
        else:raise RuntimeError('interrupted legacy boot was converted')
        if ((work/'bad.img').exists() or (work/'bad-work').exists()
                or upgrade.digest(target.image)!=original):
            raise RuntimeError('refused legacy conversion allocated or changed its input')
        info=matrix.start(target,'ata',expect_sweep=True)
        client=matrix.recovery.served.sm.Client(work,target.port)
        client.trust(info['public'])
        halted=matrix.recovery.ssh(client,key,'shutdown')
        if halted.returncode!=0 or target.status(300)!='3':
            raise RuntimeError('legacy boot did not halt successfully')
        source=target.image
        original=upgrade.digest(source)
        record=upgrade.clean_history(target.tree(),target.serial())
        # A legacy non-ledger writer can leave all halt facts unchanged.
        # Its whole-image change must nevertheless invalidate the halt seal.
        late=work/'post-halt-write.img';shutil.copyfile(source,late)
        late_work=work/'post-halt-write';late_work.mkdir(mode=0o700)
        release.oi.import_boots(target.kernel,late,[(4,[('/etc/motd',b'post-halt host write\n')])],
                                late_work,root=target.root,fresh=True)
        if upgrade.clean_history(upgrade.inspect(late)[0],target.serial())!=record:
            raise RuntimeError('negative fixture did not preserve the stale halt facts')
        try:
            upgrade.convert(late,work/'late-output.img',target.serial(),work/'late-conversion',
                target.kernel,oi=release.oi,release=release,
                attest_no_writes_since_halt=True,halt_image_sha256=original)
        except ValueError as error:
            if 'image changed since' not in str(error):raise
            result['post_halt_write_refused']=str(error)
        else:raise RuntimeError('post-halt host write was converted with a stale halt hash')
        if (work/'late-output.img').exists() or (work/'late-conversion').exists():
            raise RuntimeError('post-halt refusal allocated conversion output')
        result['conversion']=upgrade.convert(source,work/'guarded.img',target.serial(),
            work/'conversion',target.kernel,oi=release.oi,release=release,
            attest_no_writes_since_halt=True,halt_image_sha256=original)
        target.image=work/'guarded.img'
        if upgrade.ledger(target.tree()['/var/state/recovery'])!=record:
            raise RuntimeError('conversion reset the charged legacy recovery history')
        target.fsd_elf=target.root/'absd-fsd.elf'
        raw,status,log=guest.cold_boot(target,'ata','guarded-bounded',served=False,
                                     worker=target.root/'commands/echo')
        serial=raw.decode(errors='replace')
        if (status!='3' or serial.count('ABSD KERNEL BOOT\n')!=1
                or 'FSD SHUTDOWN FINALIZED status=0' not in serial
                or target.tree()[guard.PATH]!=guard.encode('clean')):
            raise RuntimeError('converted disk did not complete its guarded boot')
        matrix.fsd_fence(serial,'none','ended')
        next_record=upgrade.ledger(target.tree()['/var/state/recovery'])
        if next_record['seq']!=record['seq']+1 or next_record['streak']!=0:
            raise RuntimeError('guarded boot did not advance the preserved legacy ledger')
        if upgrade.digest(source)!=original:raise RuntimeError('legacy source changed')
        result.update(verdict='PASS',preserved_record=record,next_record=next_record,
                      source_unchanged=True,guarded_boot=str(log))
        print('STORAGE FENCE UPGRADE OK unclean_refused=true history_preserved=true source_unchanged=true',flush=True)
    except BaseException as error:
        result.update(verdict='FAIL_OR_INCOMPLETE',error=repr(error));raise
    finally:
        target.stop()
        (work/'result.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
