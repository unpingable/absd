-- cports SQLite case: indexes (CPORTS-HARNESS.md 5.3). Runs on the database
-- create-insert.sql left.
.bail on
.mode list
CREATE INDEX t1b ON t1(b);
CREATE UNIQUE INDEX t1c ON t1(c);
EXPLAIN QUERY PLAN SELECT a FROM t1 WHERE b=42;
SELECT a FROM t1 WHERE b BETWEEN 100 AND 110 ORDER BY b, a;
SELECT count(*) FROM t1 WHERE c > 'row-04990';
SELECT count(*) FROM t1 INDEXED BY t1c WHERE c LIKE 'row-001%';
PRAGMA integrity_check;
