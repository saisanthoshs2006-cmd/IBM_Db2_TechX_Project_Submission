"""Allow-lists and deny-lists used by the SQL guard. Everything not listed here is rejected."""
from __future__ import annotations

# Schemas the copilot may never read, whatever DATA_SOURCE says. Any schema starting with SYS
# is also denied (catalog, monitor, admin and tools schemas).
HARD_DENIED_SCHEMAS = frozenset({"DB2INST1", "DB2INTEL", "DB2INTEL_TRIAL", "NULLID", "SQLJ"})
DENIED_SCHEMA_PREFIXES = ("SYS",)

# Fully qualified system objects a generated query may read.
READABLE_SYSTEM_OBJECTS = frozenset({("SYSIBM", "SYSDUMMY1")})

# Built-in functions a generated query may call (unqualified only). Db2 resolves unqualified
# names along CURRENT PATH, so preflight also proves no user-defined function shadows these.
AGGREGATE_FUNCTIONS = frozenset({
    "AVG", "COUNT", "COUNT_BIG", "MAX", "MIN", "STDDEV", "SUM", "VARIANCE",
})
RANKING_FUNCTIONS = frozenset({  # require OVER (...)
    "DENSE_RANK", "FIRST_VALUE", "LAG", "LAST_VALUE", "LEAD", "NTILE", "RANK", "ROW_NUMBER",
})
SCALAR_FUNCTIONS = frozenset({
    "ABS", "ADD_MONTHS", "BIGINT", "CEIL", "CEILING", "CHAR", "COALESCE", "CONCAT", "DATE", "DAY",
    "DAYNAME", "DAYOFWEEK", "DAYS", "DAYS_BETWEEN", "DEC", "DECIMAL", "DIGITS", "DOUBLE", "FLOOR",
    "GREATEST", "HOUR", "INT", "INTEGER", "LAST_DAY", "LCASE", "LEAST", "LEFT", "LENGTH", "LOCATE",
    "LOWER", "LPAD", "LTRIM", "MINUTE", "MOD", "MONTH", "MONTHNAME", "MONTHS_BETWEEN", "NULLIF",
    "NVL", "POWER", "QUARTER", "REPLACE", "RIGHT", "ROUND", "RPAD", "RTRIM", "SIGN", "SQRT",
    "SUBSTR", "TIMESTAMP", "TO_CHAR", "TRIM", "TRUNC", "TRUNCATE", "UCASE", "UPPER", "VALUE",
    "VARCHAR", "VARCHAR_FORMAT", "WEEK", "YEAR",
})
ALLOWED_FUNCTIONS = AGGREGATE_FUNCTIONS | RANKING_FUNCTIONS | SCALAR_FUNCTIONS
# Special forms parsed by dedicated grammar rules.
SPECIAL_FORMS = frozenset({"CAST", "EXTRACT"})

CAST_TYPES = frozenset({
    "BIGINT", "BOOLEAN", "CHAR", "CHARACTER", "DATE", "DEC", "DECFLOAT", "DECIMAL", "DOUBLE",
    "FLOAT", "INT", "INTEGER", "NUMERIC", "REAL", "SMALLINT", "TIME", "TIMESTAMP", "VARCHAR",
})

DURATIONS = frozenset({
    "DAY", "DAYS", "MONTH", "MONTHS", "YEAR", "YEARS", "HOUR", "HOURS", "MINUTE", "MINUTES",
    "SECOND", "SECONDS",
})
EXTRACT_FIELDS = frozenset({"YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND"})

# Words that can never be a table, column, alias or CTE name. Statement keywords outside the
# SELECT grammar are listed so they are reported clearly instead of being taken as names.
RESERVED = frozenset({
    "ALL", "ALLOCATE", "ALTER", "AND", "ANY", "AS", "ASC", "AUDIT", "BEGIN", "BETWEEN", "BY",
    "CALL", "CASE", "CAST", "CLOSE", "COMMENT", "COMMIT", "CONNECT", "CREATE", "CROSS", "CS",
    "CURRENT", "CURSOR", "DECLARE", "DEFAULT", "DELETE", "DESC", "DESCRIBE", "DISTINCT", "DO",
    "DROP", "ELSE", "END", "ESCAPE", "EXCEPT", "EXECUTE", "EXISTS", "EXPLAIN", "EXTRACT", "FALSE",
    "FETCH", "FINAL", "FIRST", "FOLLOWING", "FOR", "FREE", "FROM", "FULL", "FUNCTION", "GET",
    "GRANT", "GROUP", "HAVING", "IF", "IMMEDIATE", "IN", "INNER", "INSERT", "INTERSECT", "INTO",
    "IS", "JOIN", "KEEP", "LABEL", "LAST", "LATERAL", "LEFT", "LIKE", "LIMIT", "LOCK", "LOCKED",
    "MERGE", "MINUS", "NEW", "NEXT", "NOT", "NULL", "NULLS", "OF", "OFFSET", "OLD", "ON", "ONLY",
    "OPEN", "OPTIMIZE", "OR", "ORDER", "OUTER", "OVER", "PARTITION", "PERIOD", "PRECEDING",
    "PREPARE", "PROCEDURE", "RANGE", "READ", "REFRESH", "RELEASE", "RENAME", "REPEAT", "REVOKE",
    "RIGHT", "ROLLBACK", "ROW", "ROWS", "RR", "RS", "SAVEPOINT", "SELECT", "SET", "SKIP", "SOME",
    "TABLE", "TABLESAMPLE", "THEN", "TRANSFER", "TRUE", "TRUNCATE", "UNBOUNDED", "UNION", "UNNEST",
    "UPDATE", "UR", "USE", "USING", "VALUES", "VERSIONS", "WHEN", "WHERE", "WHILE", "WITH",
    "WITHIN", "XMLTABLE",
}) | DURATIONS

# Clause words that get a specific explanation when they appear where they are not allowed.
STATEMENT_WORDS = frozenset({
    "ALTER", "CALL", "COMMENT", "COMMIT", "CREATE", "DECLARE", "DELETE", "DROP", "EXECUTE",
    "EXPLAIN", "GRANT", "INSERT", "LOCK", "MERGE", "PREPARE", "REFRESH", "RENAME", "REVOKE",
    "ROLLBACK", "SAVEPOINT", "SET", "TRANSFER", "TRUNCATE", "UPDATE", "VALUES",
})

# Request markers are added by the guard after parsing; user SQL may never contain one.
MARKER_PREFIX = "DB2INTEL_REQ_"

MAX_SQL_CHARS = 20_000
MAX_TOKENS = 5_000
MAX_NESTING = 64
