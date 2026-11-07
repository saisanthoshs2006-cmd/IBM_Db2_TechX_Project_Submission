import pytest

from db2intel.db.sql_script import SqlScriptError, checksum, mask_literals, split_statements


def test_splits_on_semicolons_and_drops_line_comments():
    text = "-- header\nCREATE SCHEMA A;\n\nCREATE TABLE A.T (X INT); -- trailing\n"
    assert split_statements(text) == ["CREATE SCHEMA A", "CREATE TABLE A.T (X INT)"]


def test_semicolons_and_dashes_inside_literals_are_preserved():
    text = "INSERT INTO A.T VALUES ('a;b', 'c--d', 'it''s');"
    assert split_statements(text) == ["INSERT INTO A.T VALUES ('a;b', 'c--d', 'it''s')"]


def test_block_comments_are_rejected():
    with pytest.raises(SqlScriptError, match="block comments"):
        split_statements("/* hidden; */ CREATE SCHEMA A;")


def test_unterminated_literal_is_rejected():
    with pytest.raises(SqlScriptError, match="unterminated"):
        split_statements("INSERT INTO A.T VALUES ('oops);")


def test_missing_final_semicolon_is_rejected():
    with pytest.raises(SqlScriptError, match="not terminated"):
        split_statements("CREATE SCHEMA A;\nCREATE SCHEMA B")


def test_checksum_ignores_line_ending_style():
    assert checksum("A;\nB;\n") == checksum("A;\r\nB;\r\n")
    assert checksum("A;\n") != checksum("B;\n")


def test_mask_literals():
    assert mask_literals("X = 'DB2INST1' AND Y = 'it''s'") == "X = '' AND Y = ''"
