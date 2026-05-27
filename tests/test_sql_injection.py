"""
Unit tests for SQL injection protection - SECURITY-3
Tests that the codebase is protected against SQL injection attacks
"""

import pytest
import sys
import os

# Add common directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))

from sql_utils import (
    validate_identifier,
    validate_table_name,
    validate_column_name,
    build_safe_update,
    build_safe_select,
    build_safe_insert,
    safe_dynamic_update,
    SQLSecurityError
)


class TestIdentifierValidation:
    """Test SQL identifier validation to prevent injection"""

    def test_valid_identifiers(self):
        """Valid SQL identifiers should pass"""
        assert validate_identifier("user_id") == "user_id"
        assert validate_identifier("table_name") == "table_name"
        assert validate_identifier("_private") == "_private"
        assert validate_identifier("column123") == "column123"

    def test_sql_injection_blocked(self):
        """SQL injection attempts should be blocked"""
        with pytest.raises(SQLSecurityError):
            validate_identifier("users; DROP TABLE users")

        with pytest.raises(SQLSecurityError):
            validate_identifier("id' OR '1'='1")

        with pytest.raises(SQLSecurityError):
            validate_identifier("column--comment")

    def test_special_characters_blocked(self):
        """Special characters should be blocked"""
        with pytest.raises(SQLSecurityError):
            validate_identifier("user name")  # Space

        with pytest.raises(SQLSecurityError):
            validate_identifier("user-id")  # Hyphen

        with pytest.raises(SQLSecurityError):
            validate_identifier("user.id")  # Dot

        with pytest.raises(SQLSecurityError):
            validate_identifier("user@id")  # At sign

    def test_sql_keywords_blocked(self):
        """SQL keywords should be blocked as identifiers"""
        with pytest.raises(SQLSecurityError):
            validate_identifier("SELECT")

        with pytest.raises(SQLSecurityError):
            validate_identifier("DROP")

        with pytest.raises(SQLSecurityError):
            validate_identifier("DELETE")

    def test_empty_and_null(self):
        """Empty or null identifiers should be rejected"""
        with pytest.raises(SQLSecurityError):
            validate_identifier("")

        with pytest.raises(SQLSecurityError):
            validate_identifier(None)

    def test_length_limit(self):
        """Very long identifiers should be rejected"""
        with pytest.raises(SQLSecurityError):
            validate_identifier("a" * 100)  # PostgreSQL limit is 63


class TestSafeUpdateBuilder:
    """Test safe UPDATE query builder"""

    def test_basic_update(self):
        """Basic UPDATE should be built correctly"""
        sql, params = build_safe_update(
            "users",
            {"name": "Alice", "age": 30},
            "id = %s",
            (123,)
        )

        assert "UPDATE users SET" in sql
        assert "name = %s" in sql
        assert "age = %s" in sql
        assert "WHERE id = %s" in sql
        assert params == ("Alice", 30, 123)

    def test_single_column_update(self):
        """Single column UPDATE should work"""
        sql, params = build_safe_update(
            "jobs",
            {"status": "completed"},
            "id = %s",
            ("job-123",)
        )

        assert sql == "UPDATE jobs SET status = %s WHERE id = %s"
        assert params == ("completed", "job-123")

    def test_invalid_table_name_blocked(self):
        """Invalid table names should be blocked"""
        with pytest.raises(SQLSecurityError):
            build_safe_update(
                "users; DROP TABLE",
                {"name": "Alice"},
                "id = %s",
                (123,)
            )

    def test_invalid_column_name_blocked(self):
        """Invalid column names should be blocked"""
        with pytest.raises(SQLSecurityError):
            build_safe_update(
                "users",
                {"name; DROP TABLE": "Alice"},
                "id = %s",
                (123,)
            )

    def test_empty_updates_rejected(self):
        """Empty updates dict should be rejected"""
        with pytest.raises(SQLSecurityError):
            build_safe_update(
                "users",
                {},
                "id = %s",
                (123,)
            )


class TestSafeSelectBuilder:
    """Test safe SELECT query builder"""

    def test_basic_select(self):
        """Basic SELECT should be built correctly"""
        sql, params = build_safe_select(
            "users",
            ["id", "name", "email"],
            "age > %s",
            (18,)
        )

        assert sql == "SELECT id, name, email FROM users WHERE age > %s"
        assert params == (18,)

    def test_select_all_columns(self):
        """SELECT * should work"""
        sql, params = build_safe_select(
            "users",
            ["*"]
        )

        assert sql == "SELECT * FROM users"
        assert params == ()

    def test_select_without_where(self):
        """SELECT without WHERE clause should work"""
        sql, params = build_safe_select(
            "users",
            ["id", "name"]
        )

        assert sql == "SELECT id, name FROM users"
        assert params == ()

    def test_invalid_table_blocked(self):
        """Invalid table name should be blocked"""
        with pytest.raises(SQLSecurityError):
            build_safe_select(
                "users; DROP TABLE",
                ["id"]
            )

    def test_invalid_column_blocked(self):
        """Invalid column name should be blocked"""
        with pytest.raises(SQLSecurityError):
            build_safe_select(
                "users",
                ["id", "name; DROP TABLE"]
            )


class TestSafeInsertBuilder:
    """Test safe INSERT query builder"""

    def test_basic_insert(self):
        """Basic INSERT should be built correctly"""
        sql, params = build_safe_insert(
            "users",
            {"name": "Bob", "age": 25, "email": "bob@example.com"}
        )

        assert "INSERT INTO users" in sql
        assert "name" in sql
        assert "age" in sql
        assert "email" in sql
        assert "VALUES" in sql
        assert params == ("Bob", 25, "bob@example.com")

    def test_single_column_insert(self):
        """Single column INSERT should work"""
        sql, params = build_safe_insert(
            "logs",
            {"message": "Test log entry"}
        )

        assert sql == "INSERT INTO logs (message) VALUES (%s)"
        assert params == ("Test log entry",)

    def test_invalid_table_blocked(self):
        """Invalid table name should be blocked"""
        with pytest.raises(SQLSecurityError):
            build_safe_insert(
                "users; DROP TABLE",
                {"name": "Alice"}
            )

    def test_invalid_column_blocked(self):
        """Invalid column name should be blocked"""
        with pytest.raises(SQLSecurityError):
            build_safe_insert(
                "users",
                {"name; DROP TABLE": "Alice"}
            )

    def test_empty_values_rejected(self):
        """Empty values dict should be rejected"""
        with pytest.raises(SQLSecurityError):
            build_safe_insert("users", {})


class TestSafeDynamicUpdate:
    """Test safe dynamic UPDATE helper"""

    def test_partial_update(self):
        """Partial UPDATE with only provided fields should work"""
        sql, params = safe_dynamic_update(
            "jobs",
            {"status": "completed", "finished_at": "2024-11-19"},
            "id",
            "job-123"
        )

        assert "UPDATE jobs SET" in sql
        assert "status = %s" in sql
        assert "finished_at = %s" in sql
        assert "WHERE id = %s" in sql
        assert params == ("completed", "2024-11-19", "job-123")

    def test_single_field_update(self):
        """Single field UPDATE should work"""
        sql, params = safe_dynamic_update(
            "agent_sessions",
            {"status": "running"},
            "id",
            "session-456"
        )

        assert sql == "UPDATE agent_sessions SET status = %s WHERE id = %s"
        assert params == ("running", "session-456")


class TestSQLInjectionAttackScenarios:
    """Integration tests for real-world SQL injection attack scenarios"""

    def test_classic_sql_injection_attack(self):
        """Classic SQL injection via string concatenation should be prevented"""
        # Attack: malicious user tries to inject SQL
        malicious_table = "users; DROP TABLE users; --"

        with pytest.raises(SQLSecurityError):
            build_safe_update(
                malicious_table,
                {"name": "Alice"},
                "id = %s",
                (1,)
            )

    def test_union_based_injection_attack(self):
        """UNION-based SQL injection should be prevented"""
        # Attack: try to use UNION to extract data
        malicious_column = "name UNION SELECT password FROM admin --"

        with pytest.raises(SQLSecurityError):
            build_safe_select(
                "users",
                ["id", malicious_column]
            )

    def test_boolean_based_injection_attack(self):
        """Boolean-based SQL injection should be prevented"""
        # Attack: try to use OR to bypass authentication
        malicious_table = "users WHERE 1=1 OR 1=1"

        with pytest.raises(SQLSecurityError):
            build_safe_select(
                malicious_table,
                ["*"]
            )

    def test_comment_based_injection_attack(self):
        """Comment-based SQL injection should be prevented"""
        # Attack: use comments to truncate query
        malicious_column = "id-- comment"

        with pytest.raises(SQLSecurityError):
            build_safe_update(
                "users",
                {malicious_column: "value"},
                "id = %s",
                (1,)
            )

    def test_stacked_queries_attack(self):
        """Stacked queries attack should be prevented"""
        # Attack: execute multiple statements
        malicious_table = "users; DELETE FROM users; SELECT * FROM users"

        with pytest.raises(SQLSecurityError):
            build_safe_insert(
                malicious_table,
                {"name": "Alice"}
            )

    def test_second_order_injection_attack(self):
        """Second-order SQL injection should be prevented"""
        # Attack: store malicious data that gets executed later
        # Even if malicious data is stored, it won't be executed
        # because we always use parameterized queries

        malicious_data = "'; DROP TABLE users; --"

        # This is SAFE - data is parameterized
        sql, params = build_safe_insert(
            "users",
            {"name": malicious_data}
        )

        # Verify the malicious string is treated as data, not SQL
        assert params == (malicious_data,)
        assert "DROP TABLE" not in sql

    def test_time_based_blind_injection_attack(self):
        """Time-based blind SQL injection should be prevented"""
        # Attack: use SLEEP/pg_sleep to detect vulnerability
        malicious_column = "id; SELECT pg_sleep(10); --"

        with pytest.raises(SQLSecurityError):
            build_safe_select(
                "users",
                [malicious_column]
            )


class TestParameterization:
    """Test that actual values are always parameterized"""

    def test_values_never_in_sql_string(self):
        """User values should never appear in SQL string"""
        dangerous_value = "'; DROP TABLE users; --"

        sql, params = build_safe_insert(
            "users",
            {"name": dangerous_value}
        )

        # SQL should only contain placeholders
        assert "%s" in sql
        assert "DROP TABLE" not in sql

        # Dangerous value should be in params (safely parameterized)
        assert dangerous_value in params

    def test_quotes_dont_break_parameterization(self):
        """Quotes in values should be safe"""
        value_with_quotes = "O'Reilly"

        sql, params = build_safe_update(
            "users",
            {"name": value_with_quotes},
            "id = %s",
            (123,)
        )

        # Value should be in params, not interpolated in SQL
        assert value_with_quotes in params
        assert "O'Reilly" not in sql  # Not directly in SQL string


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
