from __future__ import annotations


def test_postgres_harness_provisions_isolated_login_roles(postgres_harness: object) -> None:
    harness = postgres_harness
    expected_roles = {"admin", "runtime", "dev", "sealer", "evaluator"}

    assert set(harness.dsns) == expected_roles
    assert set(harness.role_names) == expected_roles
    assert len(set(harness.role_names.values())) == len(expected_roles)
    assert "dsns=" not in repr(harness)

    for capability in harness.dsns:
        with harness.connect(capability) as connection:
            row = connection.execute(
                """
                SELECT current_user,
                       current_database(),
                       current_setting('server_version_num')::integer,
                       current_setting('TimeZone'),
                       rolcanlogin,
                       rolsuper,
                       rolcreaterole,
                       rolcreatedb
                  FROM pg_roles
                 WHERE rolname = current_user
                """
            ).fetchone()

        assert row is not None
        (
            current_user,
            database,
            version,
            timezone,
            can_login,
            superuser,
            create_role,
            create_db,
        ) = row
        assert current_user == harness.role_names[capability]
        assert database == harness.database_name
        assert version // 10000 == 17
        assert timezone == "UTC"
        assert can_login is True

        privileged = capability == "admin"
        assert superuser is privileged
        assert create_role is privileged
        assert create_db is privileged
