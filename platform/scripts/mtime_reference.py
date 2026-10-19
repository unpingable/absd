"""Host qualification reference from actual committed filesystem records.

A visible ancestor of mounts remains a real filesystem object. Its readonly
view does not imply an unknown timestamp. This reads the independent image
parser, never std output. Sampling retries only a transient commit snapshot.
"""
import time
import absd_fs
import ssh_absd


def records(image):
    for attempt in range(20):
        try:
            region = absd_fs.fs_region(image, ssh_absd.DEVICE_SECTORS)
            selected = absd_fs.select(region)
            result = absd_fs.tree(region, selected)
            result['/'] = next(r for r in selected['records'] if r['serial'] == absd_fs.ROOT)
            return result
        except absd_fs.Refused:
            if attempt == 19:
                raise
            time.sleep(0.25)


def timestamp(seconds, detailed=False):
    if not isinstance(seconds, int) or not 0 <= seconds <= (1 << 64) - 1:
        raise ValueError('mtime reference requires a format-2 timestamp')
    if seconds == 0:
        return 'unknown' if detailed else '-'
    return time.strftime('%Y-%m-%dT%H:%M:%SZ' if detailed else '%Y-%m-%d %H:%M', time.gmtime(seconds))


def root_listing(snapshot, physical):
    # The existing command fixture's exact six names/flags/links/sizes remain
    # fixed. Only the new time field comes from each actual backing object.
    return ''.join('d -- 1 0 '+timestamp(snapshot[physical('/'+name)]['mtime'])+' '+name+'/\n'
                   for name in ('bin', 'etc', 'home', 'share', 'tmp', 'var')).encode()
