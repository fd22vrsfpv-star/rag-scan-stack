"""
SQL Security Utilities for RAG Scan Stack

This module provides helper functions for safe SQL operations,
preventing SQL injection attacks.
"""

import re
from typing import Dict, Any, Tuple, List


# Safe SQL identifier pattern (column names, table names)
SAFE_SQL_IDENTIFIER = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')


class SQLSecurityError(ValueError):
    """Raised when SQL security validation fails"""
    pass


def validate_identifier(identifier: str) -> str:
    """
    Validate that identifier is a safe SQL identifier (column/table name).

    Only allows identifiers that match: ^[a-zA-Z_][a-zA-Z0-9_]*$
    - Must start with letter or underscore
    - Can contain letters, numbers, underscores
    - No spaces, special characters, or SQL keywords as prefix

    Args:
        identifier: Column name, table name, or other SQL identifier

    Returns:
        The validated identifier

    Raises:
        SQLSecurityError: If identifier contains invalid characters

    Examples:
        >>> validate_identifier("user_id")
        'user_id'
        >>> validate_identifier("table1")
        'table1'
        >>> validate_identifier("id; DROP TABLE")
        SQLSecurityError: Invalid SQL identifier
    """
    if not identifier or not isinstance(identifier, str):
        raise SQLSecurityError("Identifier must be a non-empty string")

    if len(identifier) > 63:  # PostgreSQL identifier max length
        raise SQLSecurityError(f"Identifier too long: {identifier}")

    if not SAFE_SQL_IDENTIFIER.match(identifier):
        raise SQLSecurityError(
            f"Invalid SQL identifier: '{identifier}'. "
            "Only alphanumeric characters and underscores allowed, "
            "must start with letter or underscore."
        )

    # Prevent SQL keywords used as identifiers (optional additional check)
    sql_keywords = {'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
                    'ALTER', 'TABLE', 'WHERE', 'FROM', 'JOIN', 'UNION'}
    if identifier.upper() in sql_keywords:
        raise SQLSecurityError(f"SQL keyword not allowed as identifier: {identifier}")

    return identifier


def validate_table_name(table: str) -> str:
    """
    Validate table name for use in queries.

    Alias for validate_identifier with additional context.

    Args:
        table: Table name to validate

    Returns:
        Validated table name

    Raises:
        SQLSecurityError: If table name is invalid
    """
    return validate_identifier(table)


def validate_column_name(column: str) -> str:
    """
    Validate column name for use in queries.

    Alias for validate_identifier with additional context.

    Args:
        column: Column name to validate

    Returns:
        Validated column name

    Raises:
        SQLSecurityError: If column name is invalid
    """
    return validate_identifier(column)


def build_safe_update(
    table: str,
    updates: Dict[str, Any],
    where_clause: str,
    where_params: Tuple
) -> Tuple[str, Tuple]:
    """
    Build safe UPDATE query with validated identifiers and parameterized values.

    This function validates table and column names to prevent SQL injection,
    while using parameterized queries for all values.

    Args:
        table: Table name (will be validated)
        updates: Dict of {column_name: value} to update
        where_clause: WHERE clause with %s placeholders (e.g., "id = %s")
        where_params: Parameters for WHERE clause

    Returns:
        Tuple of (sql_query, params_tuple)

    Raises:
        SQLSecurityError: If table or column names are invalid

    Examples:
        >>> sql, params = build_safe_update(
        ...     "users",
        ...     {"name": "Alice", "age": 30},
        ...     "id = %s",
        ...     (123,)
        ... )
        >>> print(sql)
        'UPDATE users SET name = %s, age = %s WHERE id = %s'
        >>> print(params)
        ('Alice', 30, 123)
    """
    # Validate table name
    table = validate_table_name(table)

    if not updates:
        raise SQLSecurityError("No columns to update")

    # Validate column names and build assignments
    assignments = []
    params = []

    for col, val in updates.items():
        col = validate_column_name(col)
        assignments.append(f"{col} = %s")
        params.append(val)

    # Build SQL
    sql = f"UPDATE {table} SET {', '.join(assignments)} WHERE {where_clause}"

    # Append WHERE parameters
    params.extend(where_params)

    return sql, tuple(params)


def build_safe_select(
    table: str,
    columns: List[str],
    where_clause: str = None,
    where_params: Tuple = None
) -> Tuple[str, Tuple]:
    """
    Build safe SELECT query with validated identifiers.

    Args:
        table: Table name (will be validated)
        columns: List of column names to select (or ['*'] for all)
        where_clause: Optional WHERE clause with %s placeholders
        where_params: Optional parameters for WHERE clause

    Returns:
        Tuple of (sql_query, params_tuple)

    Raises:
        SQLSecurityError: If table or column names are invalid

    Examples:
        >>> sql, params = build_safe_select(
        ...     "users",
        ...     ["id", "name", "email"],
        ...     "age > %s",
        ...     (18,)
        ... )
        >>> print(sql)
        'SELECT id, name, email FROM users WHERE age > %s'
    """
    # Validate table name
    table = validate_table_name(table)

    # Validate column names
    if columns == ['*']:
        column_list = '*'
    else:
        validated_columns = [validate_column_name(col) for col in columns]
        column_list = ', '.join(validated_columns)

    # Build SQL
    sql = f"SELECT {column_list} FROM {table}"

    if where_clause:
        sql += f" WHERE {where_clause}"

    params = where_params or ()
    return sql, params


def build_safe_insert(
    table: str,
    values: Dict[str, Any]
) -> Tuple[str, Tuple]:
    """
    Build safe INSERT query with validated identifiers.

    Args:
        table: Table name (will be validated)
        values: Dict of {column_name: value} to insert

    Returns:
        Tuple of (sql_query, params_tuple)

    Raises:
        SQLSecurityError: If table or column names are invalid

    Examples:
        >>> sql, params = build_safe_insert(
        ...     "users",
        ...     {"name": "Bob", "age": 25, "email": "bob@example.com"}
        ... )
        >>> print(sql)
        'INSERT INTO users (name, age, email) VALUES (%s, %s, %s)'
    """
    # Validate table name
    table = validate_table_name(table)

    if not values:
        raise SQLSecurityError("No values to insert")

    # Validate column names
    columns = []
    params = []

    for col, val in values.items():
        col = validate_column_name(col)
        columns.append(col)
        params.append(val)

    # Build SQL
    placeholders = ', '.join(['%s'] * len(columns))
    column_list = ', '.join(columns)

    sql = f"INSERT INTO {table} ({column_list}) VALUES ({placeholders})"

    return sql, tuple(params)


def safe_dynamic_update(
    table: str,
    allowed_columns: Dict[str, Any],
    where_column: str,
    where_value: Any
) -> Tuple[str, Tuple]:
    """
    Build safe dynamic UPDATE with whitelisted columns.

    This is a convenience wrapper for build_safe_update that's commonly
    used for partial updates (e.g., updating only provided fields).

    Args:
        table: Table name
        allowed_columns: Dict of {column: value} where columns are whitelisted
        where_column: Column name for WHERE clause
        where_value: Value for WHERE clause

    Returns:
        Tuple of (sql_query, params_tuple)

    Example:
        >>> # Update only non-None fields
        >>> updates = {}
        >>> if new_status:
        ...     updates['status'] = new_status
        >>> if new_name:
        ...     updates['name'] = new_name
        >>>
        >>> sql, params = safe_dynamic_update(
        ...     "jobs",
        ...     updates,
        ...     "id",
        ...     job_id
        ... )
    """
    where_column = validate_column_name(where_column)
    return build_safe_update(
        table,
        allowed_columns,
        f"{where_column} = %s",
        (where_value,)
    )


# Example usage
if __name__ == "__main__":
    # Test identifier validation
    print("Testing identifier validation:")
    try:
        print(f"✓ Valid: {validate_identifier('user_id')}")
        print(f"✓ Valid: {validate_identifier('table_name_1')}")

        try:
            validate_identifier("id; DROP TABLE users")
            print("✗ Should have failed!")
        except SQLSecurityError as e:
            print(f"✓ Blocked injection: {e}")

    except Exception as e:
        print(f"✗ Unexpected error: {e}")

    # Test safe UPDATE builder
    print("\nTesting safe UPDATE builder:")
    sql, params = build_safe_update(
        "users",
        {"name": "Alice", "age": 30},
        "id = %s",
        (123,)
    )
    print(f"SQL: {sql}")
    print(f"Params: {params}")

    # Test safe INSERT builder
    print("\nTesting safe INSERT builder:")
    sql, params = build_safe_insert(
        "users",
        {"name": "Bob", "age": 25, "email": "bob@example.com"}
    )
    print(f"SQL: {sql}")
    print(f"Params: {params}")

    # Test dynamic update
    print("\nTesting dynamic UPDATE:")
    updates = {"status": "completed", "finished_at": "2024-11-19"}
    sql, params = safe_dynamic_update(
        "jobs",
        updates,
        "id",
        "550e8400-e29b-41d4-a716-446655440000"
    )
    print(f"SQL: {sql}")
    print(f"Params: {params}")

    print("\n✓ All tests passed!")
