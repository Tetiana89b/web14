import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from autorizetion import app, User, get_db


@pytest.fixture(scope="module")
def test_client():
    with TestClient(app) as client:
        yield client


def test_login_user(test_client: TestClient, db: Session):
    # Підготовка тестових даних
    user = User(email="test@example.com", password="password")
    db.add(user)
    db.commit()

    # Виконання запиту POST /login/ з тестовими даними
    response = test_client.post(
        "/login/", data={"username": "test@example.com", "password": "password"})

    # Перевірка статусу відповіді
    assert response.status_code == 200

    # Перевірка наявності поля "access_token" у відповіді
    assert "access_token" in response.json()
