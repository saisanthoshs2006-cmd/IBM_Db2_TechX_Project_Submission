import pytest

from db2intel.config import ConfigError, load_dotenv, load_settings


def test_password_is_never_in_repr():
    s = load_settings({"DB2_PASSWORD": "s3cret-value"})
    assert "s3cret-value" not in repr(s) and "s3cret-value" not in str(s.db2)


def test_connection_string_requires_password():
    with pytest.raises(ConfigError, match="DB2_PASSWORD"):
        load_settings({}).db2.connection_string()


def test_connection_string_shape():
    cs = load_settings({"DB2_PASSWORD": "x", "DB2_DATABASE": "testdb"}).db2.connection_string()
    assert cs.startswith("DATABASE=TESTDB;HOSTNAME=localhost;PORT=50000;PROTOCOL=TCPIP;UID=db2inst1;")


def test_dotenv_does_not_override_existing_env(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("DB2_HOST=fromfile\nDB2_PORT=50001\n# comment\n")
    env = {"DB2_HOST": "fromenv"}
    load_dotenv(env_file, env)
    assert env == {"DB2_HOST": "fromenv", "DB2_PORT": "50001"}


def test_migration_targets_default_to_testdb():
    assert load_settings({}).migration.allowed_databases == ("TESTDB",)


def test_bad_integer_is_reported():
    with pytest.raises(ConfigError, match="DB2_PORT"):
        load_settings({"DB2_PORT": "fifty"})


# ---- credential and connection-string validation (no database) ---------------------------
FAKE_TEST_SECRET = "example-fake-test-secret;DATABASE=SAMPLE"  # fake test value; would inject a second DATABASE= keyword if accepted


@pytest.mark.parametrize("env,setting", [
    ({"DB2_PASSWORD": FAKE_TEST_SECRET}, "DB2_PASSWORD"),
    ({"DB2_PASSWORD": "abc{def}"}, "DB2_PASSWORD"),
    ({"DB2_PASSWORD": "line\nbreak"}, "DB2_PASSWORD"),
    ({"DB2_PASSWORD": "x", "DB2_DATABASE": "TESTDB;HOSTNAME=evil.example"}, "DB2_DATABASE"),
    ({"DB2_PASSWORD": "x", "DB2_DATABASE": "TOOLONGNAME"}, "DB2_DATABASE"),
    ({"DB2_PASSWORD": "x", "DB2_HOST": "localhost;PORT=1"}, "DB2_HOST"),
    ({"DB2_PASSWORD": "x", "DB2_HOST": "local host"}, "DB2_HOST"),
    ({"DB2_PASSWORD": "x", "DB2_USER": "db2inst1;PWD=y"}, "DB2_USER"),
    ({"DB2_PASSWORD": "x", "DB2_PORT": "70000"}, "DB2_PORT"),
    ({"DB2_PASSWORD": "x", "DB2_PORT": "0"}, "DB2_PORT"),
])
def test_invalid_connection_settings_are_rejected_before_connecting(env, setting):
    with pytest.raises(ConfigError, match=setting) as info:
        load_settings(env).db2.connection_string()
    assert env["DB2_PASSWORD"] not in str(info.value) or env["DB2_PASSWORD"] == "x"


def test_password_value_never_appears_in_validation_errors():
    with pytest.raises(ConfigError) as info:
        load_settings({"DB2_PASSWORD": FAKE_TEST_SECRET}).db2.connection_string()
    assert FAKE_TEST_SECRET not in str(info.value) and "example-fake-test-secret" not in str(info.value)


@pytest.mark.parametrize("env", [
    {"DB2_PASSWORD": "Str0ng!Pass#word-2026"},
    {"DB2_PASSWORD": "x", "DB2_HOST": "127.0.0.1"},
    {"DB2_PASSWORD": "x", "DB2_HOST": "::1"},
    {"DB2_PASSWORD": "x", "DB2_HOST": "db2.internal.example.com", "DB2_DATABASE": "sample", "DB2_USER": "app.user"},
])
def test_valid_settings_build_a_connection_string(env):
    cs = load_settings(env).db2.connection_string()
    assert cs.count("DATABASE=") == 1 and cs.count("PWD=") == 1 and cs.endswith(";")


def test_offline_settings_load_does_not_require_valid_credentials():
    """plan / tests must not depend on database credentials: validation happens only when connecting."""
    s = load_settings({"DB2_PASSWORD": FAKE_TEST_SECRET, "DB2_DATABASE": "NOT;VALID"})
    assert s.db2.database == "NOT;VALID"


def test_describe_names_the_target_without_the_password():
    d = load_settings({"DB2_PASSWORD": "s3cret-value"}).db2.describe()
    assert d == "database TESTDB at localhost:50000 as user db2inst1" and "s3cret" not in d
