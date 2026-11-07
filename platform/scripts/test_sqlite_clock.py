#!/usr/bin/env python3
"""Actual pinned Unix VFS and SQL clock refusal/success controls; no guest."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent.parent


class SqliteClock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        upstream = Path(os.environ.get('ABSD_CPORTS_UPSTREAM', ROOT.parent/'upstream'))
        archive = upstream/'sqlite-amalgamation/dl/sqlite-amalgamation-3540000.zip'
        original = upstream/'sqlite-amalgamation/absd/sqlite-amalgamation-3540000/sqlite3.c'
        if not archive.is_file() or not original.is_file():
            raise unittest.SkipTest('stage pinned SQLite via stage-cports.sh before this host control')
        row = next(line.split('\t') for line in (ROOT/'cports/programs.tsv').read_text().splitlines()
                   if line.startswith('sqlite-amalgamation\t'))
        if hashlib.sha256(archive.read_bytes()).hexdigest() != row[3]:
            raise AssertionError('staged SQLite archive does not match programs.tsv')
        with zipfile.ZipFile(archive) as source:
            if original.read_bytes() != source.read('sqlite-amalgamation-3540000/sqlite3.c'):
                raise AssertionError('staged SQLite differs from pinned archive')
        cls.temp = tempfile.TemporaryDirectory(prefix='sqlite-clock-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.work = Path(cls.temp.name)
        output = cls.work/'ports'
        # This target is the actual ABSD amalgamation preparation rule; prior
        # source has no preparation target, so compile its actual input there.
        adapted = output/'obj/absd/sqlite/sqlite3.c'
        makefile = (ROOT/'cports/build/sqlite.mk').read_text()
        if '$(SQL_O)/sqlite3.c:' in makefile:
            subprocess.run(['make', '--no-print-directory', '-f', str(ROOT/'cports/build/Makefile'),
                            'ROOT='+str(ROOT), 'CAMP='+str(ROOT.parent), 'UP='+str(upstream),
                            'OUT='+str(output), 'SIDE=absd', str(adapted)], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            adapted = original
        harness = cls.work/'clock.c'
        harness.write_text('''#define gettimeofday test_gettimeofday
#include "'''+str(adapted)+'''"
#undef gettimeofday
static int refuse;
int test_gettimeofday(struct timeval *tv, void *tz) {
  (void)tz;
  /* Deterministic unspecified output on error: the caller must ignore it. */
  tv->tv_sec = refuse ? 0 : 1700000000;
  tv->tv_usec = refuse ? 0 : 123000;
  return refuse ? -1 : 0;
}
int main(int argc, char **argv) {
  sqlite3_int64 instant = -123;
  sqlite3 *db = 0;
  sqlite3_stmt *stmt = 0;
  refuse = argc > 1 && argv[1][0] == 'f';
  printf("vfs_rc=%d\\n", unixCurrentTimeInt64(0, &instant));
  printf("instant=%lld\\n", (long long)instant);
  if(sqlite3_open(":memory:", &db) != SQLITE_OK) return 20;
  if(sqlite3_prepare_v2(db, "SELECT strftime('%Y-%m-%d %H:%M:%f','now')", -1, &stmt, 0) != SQLITE_OK) return 21;
  if(sqlite3_step(stmt) != SQLITE_ROW) return 22;
  printf("sql_type=%d\\n", sqlite3_column_type(stmt, 0));
  const unsigned char *text = sqlite3_column_text(stmt, 0);
  printf("sql_text=%s\\n", text ? (const char *)text : "NULL");
  sqlite3_finalize(stmt);
  return sqlite3_close(db);
}
''')
        cls.binary = cls.work/'clock'
        flags = ['-O0', '-DSQLITE_OS_UNIX=1', '-DSQLITE_THREADSAFE=0', '-DSQLITE_OMIT_LOAD_EXTENSION',
                 '-DSQLITE_ENABLE_LOCKING_STYLE=0', '-DSQLITE_OMIT_WAL', '-DSQLITE_MAX_MMAP_SIZE=0',
                 '-DSQLITE_TEMP_STORE=3', '-D_GNU_SOURCE']
        subprocess.run(['cc', *flags, '-I'+str(original.parent), str(harness), '-lm', '-o', str(cls.binary)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def result(self, mode):
        result = subprocess.run([str(self.binary), mode], check=True, capture_output=True, text=True)
        return dict(line.split('=', 1) for line in result.stdout.splitlines())

    def test_gettimeofday_failure_refuses_vfs_and_returns_sql_null(self):
        self.assertEqual(self.result('failure'), {'vfs_rc': '1', 'instant': '-123',
                                                'sql_type': '5', 'sql_text': 'NULL'})

    def test_success_keeps_julian_milliseconds_and_sql_calendar_value(self):
        self.assertEqual(self.result('success'), {'vfs_rc': '0', 'instant': '212566760000123',
                                                'sql_type': '3', 'sql_text': '2023-11-14 22:13:20.123'})


if __name__ == '__main__': unittest.main()
