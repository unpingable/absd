-- cports SQLite case: temporary storage in memory (SQLITE_TEMP_STORE=3, SPEC A18)
-- past the 32 MiB heap window. A sort of 40,000 rows of 1,000-byte blobs needs
-- about 40 MB of temporary space: on ABSD it must end as a defined SQLITE_NOMEM
-- ("out of memory"), the process alive to report it and the database intact;
-- the Linux reference (the same SQLITE_TEMP_STORE=3) keeps the sort in its
-- unbounded heap and succeeds.
.mode list
CREATE TABLE t(k INTEGER PRIMARY KEY, v TEXT);
INSERT INTO t VALUES(1, 'before');
WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 40000)
  SELECT count(*) FROM (SELECT x, zeroblob(1000) || x AS b FROM c ORDER BY b);
SELECT 'still running', count(*) FROM t;
PRAGMA integrity_check;
