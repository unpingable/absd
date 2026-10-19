-- cports SQLite case: create and insert (CPORTS-HARNESS.md 5.3).
.bail on
.mode list
.headers off
PRAGMA journal_mode=DELETE;
CREATE TABLE t1(a INTEGER PRIMARY KEY, b INTEGER, c TEXT);
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<5000)
  INSERT INTO t1 SELECT i, (i*7919)%10007, printf('row-%05d-%s', i, hex(i*i)) FROM n;
CREATE TABLE t2 AS SELECT b, count(*) AS k FROM t1 GROUP BY b;
SELECT count(*), sum(b), min(c), max(c) FROM t1;
SELECT count(*), sum(k) FROM t2;
SELECT a, b, c FROM t1 WHERE a IN (1, 2500, 5000);
PRAGMA integrity_check;
