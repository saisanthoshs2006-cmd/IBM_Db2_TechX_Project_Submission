"""Execution gates: restricted principal, audit fail-closed, timeout and fetch cap. Fake responses only."""
import dataclasses

import pytest

from db2intel.db.connection import DbError
from db2intel.guard import execution as E
from db2intel.guard.analysis import GuardDecision
from db2intel.guard.audit import AuditUnavailable, DisabledAuditSink, make_record
from db2intel.guard.execution import PrincipalError, QueryResult, execute_approved, verify_restricted_principal
from guard_fakes import CTX, no_db_driver  # noqa: F401

RID = "12345678-1234-5678-1234-567812345678"
SQL = "SELECT C.COMPANY_NAME FROM DB2INTEL_DEMO.CUSTOMER C FETCH FIRST 500 ROWS ONLY"
APPROVED = GuardDecision(RID, "APPROVED", "approved", "all checks passed", sql=SQL, estimated_cost=7.0)
NO = "N"


def auth_row(name, user=NO, group=NO, public=NO, role_user=NO, role_group=NO, role_public=NO, d_role=NO):
    return (name, user, group, public, role_user, role_group, role_public, d_role)


def tab_row(schema, table, grantee="COPILOT_RO", gtype="U", select="Y", **writes):
    w = {k: writes.get(k, NO) for k in ("control", "alter", "delete", "index", "insert", "ref", "update")}
    return (schema, table, grantee, gtype, w["control"], w["alter"], w["delete"], w["index"], w["insert"], w["ref"], select, w["update"])


class FakeExec:
    def __init__(self, user="COPILOT_RO", authorities=None, groups=(), roles=(), tabauth=None,
                 result=None, error=None, rollback_error=None):
        self.user, self.groups, self.roles, self.error, self.rollback_error = user, groups, roles, error, rollback_error
        self.authorities = authorities if authorities is not None else [auth_row("CONNECT", public="Y"), auth_row("DBADM")]
        self.tabauth = tabauth if tabauth is not None else [
            tab_row("DB2INTEL_DEMO", "CUSTOMER"), tab_row("SYSCAT", "TABLES", "PUBLIC", "G")]
        self.result = result or QueryResult(("COMPANY_NAME",), (("Acme",), ("Globex",)), False)
        self.calls = []

    def query(self, sql, params=()):
        self.calls.append(("query", sql, tuple(params)))
        if sql == E.SESSION_USER_SQL:
            return [(self.user,)]
        if sql == E.AUTHORITIES_SQL:
            return self.authorities
        if sql == E.GROUPS_SQL:
            return [(g,) for g in self.groups]
        if sql == E.ROLES_SQL:
            return [(r,) for r in self.roles]
        if sql.startswith(E.TABAUTH_SQL):
            pairs = set(zip(params[::2], params[1::2]))
            return [r for r in self.tabauth if (r[3], r[2]) in pairs]
        raise AssertionError(sql)

    def execute_capped(self, sql, max_rows, timeout_seconds):
        self.calls.append(("execute_capped", sql, max_rows, timeout_seconds))
        if self.error:
            raise self.error
        return self.result

    def rollback(self):
        self.calls.append(("rollback",))
        if self.rollback_error:
            raise self.rollback_error

    def executed(self):
        return [c for c in self.calls if c[0] == "execute_capped"]


class ReadyAudit:
    def __init__(self, fail=False, ready=True):
        self.records, self.fail, self._ready = [], fail, ready

    def ready(self):
        if isinstance(self._ready, Exception):
            raise self._ready
        return self._ready

    def write(self, record):
        if self.fail:
            raise self.fail
        self.records.append(record)


def run(fake=None, audit=None, decision=APPROVED):
    fake = fake or FakeExec()
    audit = audit if audit is not None else ReadyAudit()
    return execute_approved(decision, fake, audit, CTX, "Who are our customers?", ("DB2INST1",)), fake, audit


# ---- happy path (possible only once a restricted user and audit exist) ----------------------
def test_restricted_user_with_audit_executes_with_limits_and_audits():
    out, fake, audit = run()
    assert out.status == "SUCCESS" and out.rows == (("Acme",), ("Globex",)) and out.columns == ("COMPANY_NAME",)
    assert fake.executed() == [("execute_capped", SQL, 500, 30)]
    assert fake.calls[-1] == ("rollback",)
    (rec,) = audit.records
    assert (rec.status, rec.row_count, rec.request_id, rec.generated_sql) == ("SUCCESS", 2, RID, SQL)


# ---- Phase 2A reality: audit disabled -> nothing runs --------------------------------------
def test_disabled_audit_refuses_execution():
    out, fake, _ = run(audit=DisabledAuditSink())
    assert (out.status, out.code) == ("BLOCKED", "audit_unavailable")
    assert fake.calls == []


@pytest.mark.parametrize("ready", [False, RuntimeError("audit db down")])
def test_audit_not_ready_refuses_execution(ready):
    out, fake, _ = run(audit=ReadyAudit(ready=ready))
    assert out.code == "audit_unavailable" and fake.executed() == []


@pytest.mark.parametrize("error", [AuditUnavailable("insert failed"), RuntimeError("disk full")])
def test_audit_write_failure_withholds_the_result(error):
    out, fake, _ = run(audit=ReadyAudit(fail=error))
    assert (out.status, out.code) == ("ERROR", "audit_failed") and out.rows == ()
    assert fake.executed()


@pytest.mark.parametrize("decision", [
    dataclasses.replace(APPROVED, status="BLOCKED"), dataclasses.replace(APPROVED, status="COST_REJECTED"),
    dataclasses.replace(APPROVED, status="ERROR"), dataclasses.replace(APPROVED, sql=None),
])
def test_only_approved_decisions_execute(decision):
    out, fake, audit = run(decision=decision)
    assert out.code == "not_approved" and fake.calls == [] and audit.records == []


# ---- restricted principal --------------------------------------------------------------------
@pytest.mark.parametrize("user", ["DB2INST1", "db2inst1", ""])
def test_admin_or_unknown_user_is_refused(user):
    out, fake, _ = run(FakeExec(user=user))
    assert out.code == "principal_not_restricted" and fake.executed() == []


@pytest.mark.parametrize("flag", ["user", "group", "public", "role_user", "role_group", "role_public", "d_role"])
def test_any_authority_beyond_connect_is_refused(flag):
    authorities = [auth_row("CONNECT", user="Y"), auth_row("DATAACCESS", **{flag: "Y"})]
    out, fake, _ = run(FakeExec(authorities=authorities))
    assert out.code == "principal_not_restricted" and "DATAACCESS" in out.reason and fake.executed() == []


def test_empty_authority_list_is_refused():
    out, _, _ = run(FakeExec(authorities=[]))
    assert out.code == "principal_not_restricted"


@pytest.mark.parametrize("write", ["control", "alter", "delete", "index", "insert", "ref", "update"])
def test_any_table_write_privilege_is_refused(write):
    out, fake, _ = run(FakeExec(tabauth=[tab_row("DB2INTEL_DEMO", "CUSTOMER", **{write: "Y"})]))
    assert out.code == "principal_not_restricted" and fake.executed() == []


def test_write_privilege_through_a_group_or_role_is_refused():
    for kind, name, extra in (("G", "ANALYSTS", {"groups": ("ANALYSTS",)}), ("R", "LOADER", {"roles": ("LOADER",)})):
        fake = FakeExec(tabauth=[tab_row("DB2INTEL_DEMO", "REGION", name, kind, insert="G")], **extra)
        out, _, _ = run(fake)
        assert out.code == "principal_not_restricted" and name in out.reason


def test_write_privilege_granted_to_public_is_refused():
    out, _, _ = run(FakeExec(tabauth=[tab_row("DB2INTEL_DEMO", "REGION", "PUBLIC", "G", delete="Y")]))
    assert out.code == "principal_not_restricted"


@pytest.mark.parametrize("grantee,gtype", [("COPILOT_RO", "U"), ("PUBLIC", "G")])
def test_select_on_protected_tables_is_refused(grantee, gtype):
    out, _, _ = run(FakeExec(tabauth=[tab_row("DB2INST1", "EMPLOYEE_SALARY", grantee, gtype)]))
    assert out.code == "principal_not_restricted" and "EMPLOYEE_SALARY" in out.reason


def test_user_select_on_catalog_is_refused_but_public_default_is_tolerated():
    out, _, _ = run(FakeExec(tabauth=[tab_row("SYSCAT", "TABLES", "COPILOT_RO", "U")]))
    assert out.code == "principal_not_restricted"
    assert verify_restricted_principal(FakeExec(), ("DB2INST1",), CTX.allowed_schemas) == "COPILOT_RO"


def test_principal_lookup_failure_is_refused():
    class Broken(FakeExec):
        def query(self, sql, params=()):
            raise DbError("SQL0551N not authorized SQLSTATE=42501", "42501")
    out, fake, _ = run(Broken())
    assert (out.code, out.sqlstate) == ("principal_unverified", "42501") and fake.executed() == []


def test_principal_error_is_permission_error():
    with pytest.raises(PrincipalError):
        verify_restricted_principal(FakeExec(user="DB2INST1"), ("DB2INST1",), CTX.allowed_schemas)


# ---- runtime failures ------------------------------------------------------------------------
def test_timeout_is_reported_audited_and_rolled_back():
    out, fake, audit = run(FakeExec(error=DbError("SQL0952N cancelled SQLSTATE=57014", "57014")))
    assert (out.status, out.code, out.sqlstate) == ("ERROR", "timeout", "57014") and "30 s" in out.reason
    assert fake.calls[-1] == ("rollback",)
    assert audit.records[0].status == "ERROR" and audit.records[0].error_sqlstate == "57014"


def test_other_execution_error_is_reported():
    out, _, audit = run(FakeExec(error=DbError("SQL0802N overflow SQLSTATE=22003", "22003")))
    assert (out.status, out.code) == ("ERROR", "execution_failed") and audit.records[0].status == "ERROR"


def test_truncated_result_is_flagged():
    out, _, _ = run(FakeExec(result=QueryResult(("A",), tuple((i,) for i in range(500)), True)))
    assert out.truncated and len(out.rows) == 500


def test_rollback_failure_after_execution_does_not_hide_the_outcome():
    out, _, _ = run(FakeExec(rollback_error=DbError("gone")))
    assert out.status == "SUCCESS"


# ---- audit records ---------------------------------------------------------------------------
def test_audit_records_fit_query_audit_columns():
    rec = make_record(request_id=RID, question="q" * 5000, generated_sql=SQL, status="BLOCKED",
                      reason="r" * 999, error_message="e" * 999)
    assert len(rec.question) == 1000 and len(rec.block_reason) == 254 and len(rec.error_message) == 500


@pytest.mark.parametrize("over", [dict(status="APPROVED"), dict(request_id="short"), dict(question=" "),
                                  dict(row_count=-1), dict(sqlstate="123")])
def test_invalid_audit_records_are_refused(over):
    base = dict(request_id=RID, question="q", generated_sql=SQL, status="SUCCESS")
    with pytest.raises(ValueError):
        make_record(**{**base, **over})


def test_disabled_sink_never_writes():
    with pytest.raises(AuditUnavailable):
        DisabledAuditSink().write(make_record(request_id=RID, question="q", generated_sql=None, status="NO_SQL"))
