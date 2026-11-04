import pytest

from secureauth.testing_center import run_security_checks
from tests.conftest import PASSWORD, csrf_token, login


def test_security_center_checks_use_isolated_test_database(app, client):
    login(client)
    response = client.post(
        "/security-center",
        data={"csrf_token": csrf_token(client, "/security-center")},
    )
    assert response.status_code == 200
    assert b"isolated temporary database" in response.data
    assert b"FAIL" not in response.data


def test_security_center_is_disabled_outside_development(app, client):
    login(client)
    app.config["ENVIRONMENT"] = "production"
    response = client.get("/security-center")
    assert response.status_code == 404


def test_security_check_results_are_real_and_all_pass():
    results = run_security_checks()
    assert len(results) >= 8
    assert all(test["status"] == "PASS" for test in results), results
