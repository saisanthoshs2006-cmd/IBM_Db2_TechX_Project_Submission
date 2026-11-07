-- =============================================================================
-- 900_teardown.sql  -  Remove ONLY the objects created by this project
-- NOT part of initialization. Run only with:
--   python -m db2intel.db.migrate teardown --confirm "DROP DB2INTEL AND DB2INTEL_DEMO"
-- Every statement must match one of exactly two forms (enforced by the runner):
--   DROP TABLE|VIEW DB2INTEL[_DEMO].<name>
--   DROP SCHEMA DB2INTEL[_DEMO] RESTRICT
-- RESTRICT makes Db2 refuse to drop a schema that still contains any object this
-- script did not name, so foreign objects are never removed. Dropping a table also
-- drops its indexes, constraints and identity sequence. Runs in one transaction.
-- Objects that are already gone (SQLSTATE 42704) are skipped, so reruns are safe
-- and teardown also works when 003 was never applied.
-- =============================================================================

DROP VIEW  DB2INTEL_DEMO.V_ORDER_SUMMARY;
DROP TABLE DB2INTEL_DEMO.ORDER_ITEM;
DROP TABLE DB2INTEL_DEMO.SALES_ORDER;
DROP TABLE DB2INTEL_DEMO.PRODUCT;
DROP TABLE DB2INTEL_DEMO.CUSTOMER;
DROP TABLE DB2INTEL_DEMO.REGION;
DROP SCHEMA DB2INTEL_DEMO RESTRICT;

-- Explain tables from 003, children before parents:
-- ACTUALS -> OPERATOR, DIAGNOSTIC_DATA -> DIAGNOSTIC, the rest -> STATEMENT -> INSTANCE.
DROP TABLE DB2INTEL.EXPLAIN_ACTUALS;
DROP TABLE DB2INTEL.EXPLAIN_DIAGNOSTIC_DATA;
DROP TABLE DB2INTEL.EXPLAIN_DIAGNOSTIC;
DROP TABLE DB2INTEL.EXPLAIN_ARGUMENT;
DROP TABLE DB2INTEL.EXPLAIN_OBJECT;
DROP TABLE DB2INTEL.EXPLAIN_OPERATOR;
DROP TABLE DB2INTEL.EXPLAIN_PREDICATE;
DROP TABLE DB2INTEL.EXPLAIN_STREAM;
DROP TABLE DB2INTEL.EXPLAIN_STATEMENT;
DROP TABLE DB2INTEL.EXPLAIN_INSTANCE;
DROP TABLE DB2INTEL.OBJECT_METRICS;

-- Application metadata from 001.
DROP TABLE DB2INTEL.QUERY_FEEDBACK;
DROP TABLE DB2INTEL.VERIFIED_QUERY_EMBEDDING;
DROP TABLE DB2INTEL.VERIFIED_QUERY;
DROP TABLE DB2INTEL.QUERY_AUDIT;
DROP TABLE DB2INTEL.SCHEMA_EMBEDDING;
DROP TABLE DB2INTEL.SCHEMA_OBJECT;
DROP TABLE DB2INTEL.DATA_SOURCE;
DROP TABLE DB2INTEL.APP_SETTING;
DROP TABLE DB2INTEL.SCHEMA_MIGRATION;
DROP SCHEMA DB2INTEL RESTRICT;
