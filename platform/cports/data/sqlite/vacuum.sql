-- cports SQLite case: VACUUM (CPORTS-HARNESS.md 5.3). Runs on the database
-- rollback.sql left. VACUUM writes a temporary database in the temp directory.
.bail on
.mode list
DELETE FROM t1 WHERE a % 3 <> 0;
SELECT count(*) FROM t1;
PRAGMA page_count;
VACUUM;
PRAGMA page_count;
SELECT count(*), sum(b) FROM t1;
PRAGMA integrity_check;
