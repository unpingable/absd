-- cports SQLite case: journal rollback (CPORTS-HARNESS.md 5.3). Runs on the
-- database index.sql left. Statement 4 fails on purpose (UNIQUE), and the
-- shell reports it on stderr with this file's relative name and exits 1 at the
-- end, on ABSD and on Linux alike.
.mode list
SELECT count(*), sum(b) FROM t1;
BEGIN;
DELETE FROM t1 WHERE a % 2 = 0;
UPDATE t1 SET c = c || '-changed' WHERE a < 100;
SELECT 'inside', count(*), count(*) FILTER (WHERE c LIKE '%-changed') FROM t1;
ROLLBACK;
SELECT 'after rollback', count(*), sum(b), count(*) FILTER (WHERE c LIKE '%-changed') FROM t1;
BEGIN;
INSERT INTO t1(b, c) VALUES(1, 'keep-1');
SAVEPOINT s1;
INSERT INTO t1(b, c) VALUES(2, 'drop-2');
ROLLBACK TO s1;
RELEASE s1;
INSERT INTO t1(a, b, c) VALUES(7000, 1, 'row-00001-31');
COMMIT;
SELECT c FROM t1 WHERE c LIKE 'keep-%' OR c LIKE 'drop-%';
SELECT 'duplicate absent', count(*) FROM t1 WHERE a=7000;
PRAGMA integrity_check;
