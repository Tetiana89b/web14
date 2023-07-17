from datetime import timedelta
import unittest
from unittest.mock import MagicMock, patch
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from autorizetion import app, ContactCreate, ContactUpdate, Contact, User, create_access_token, verify_password, authenticate_user, get_user_by_email, get_password_hash, get_current_user


class UserRepositoryTestCase(unittest.TestCase):
    @classmethod
    def test_contact_create(self):
        contact_data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
            "phone_number": "123456789",
            "birthday": "1990-01-01",
            "extra_data": "Some extra data"
        }
        contact = ContactCreate(**contact_data)
        self.assertEqual(contact.first_name, "John")
        self.assertEqual(contact.last_name, "Doe")
        self.assertEqual(contact.email, "john.doe@example.com")
        self.assertEqual(contact.phone_number, "123456789")
        self.assertEqual(contact.birthday, "1990-01-01")
        self.assertEqual(contact.extra_data, "Some extra data")

    def test_contact_update(self):
        contact_data = {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
            "phone_number": "123456789",
            "birthday": "1990-01-01",
            "extra_data": "Some extra data"
        }
        contact = ContactUpdate(**contact_data)
        self.assertEqual(contact.first_name, "John")
        self.assertEqual(contact.last_name, "Doe")
        self.assertEqual(contact.email, "john.doe@example.com")
        self.assertEqual(contact.phone_number, "123456789")
        self.assertEqual(contact.birthday, "1990-01-01")
        self.assertEqual(contact.extra_data, "Some extra data")

    def test_contact(self):
        contact_data = {
            "id": 1,
            "first_name": "John",
            "last_name": "Doe",
            "email": "john.doe@example.com",
            "phone_number": "123456789",
            "birthday": "1990-01-01",
            "extra_data": "Some extra data"
        }
        contact = Contact(**contact_data)
        self.assertEqual(contact.id, 1)
        self.assertEqual(contact.first_name, "John")
        self.assertEqual(contact.last_name, "Doe")
        self.assertEqual(contact.email, "john.doe@example.com")
        self.assertEqual(contact.phone_number, "123456789")
        self.assertEqual(contact.birthday, "1990-01-01")
        self.assertEqual(contact.extra_data, "Some extra data")

    @classmethod
    def setUpClass(cls):
        cls.session = MagicMock(spec=Session)
        cls.user = User(id=1)

    def test_create_access_token(self):
        user_data = {
            "sub": "test@example.com"
        }
        access_token = create_access_token(
            user_data, expires_delta=timedelta(minutes=30))
        self.assertIsNotNone(access_token)

    def test_verify_password(self):
        password = "password123"
        hashed_password = get_password_hash(password)
        result = verify_password(password, hashed_password)
        self.assertTrue(result)

    def test_authenticate_user(self):
        email = "test@example.com"
        password = "password123"
        user = User(email=email, hashed_password=get_password_hash(password))
        self.session.query().filter().first.return_value = user

        result = authenticate_user(self.session, email, password)
        self.assertEqual(result, user)

    def test_authenticate_user_invalid_credentials(self):
        email = "test@example.com"
        password = "password123"
        self.session.query().filter().first.return_value = None

        with self.assertRaises(HTTPException) as context:
            authenticate_user(self.session, email, password)

        self.assertEqual(context.exception.status_code,
                         status.HTTP_401_UNAUTHORIZED)

    def test_get_user_by_email(self):
        email = "test@example.com"
        user = User(email=email)
        self.session.query().filter().first.return_value = user

        result = get_user_by_email(self.session, email)
        self.assertEqual(result, user)

    def test_get_user_by_email_not_found(self):
        email = "test@example.com"
        self.session.query().filter().first.return_value = None

        result = get_user_by_email(self.session, email)
        self.assertIsNone(result)

    def test_get_current_user(self):
        token = "test-token"
        payload = {"sub": "test@example.com"}
        self.session.query().filter().first.return_value = self.user

        result = get_current_user(token, self.session)
        self.assertEqual(result, self.user)

    def test_get_current_user_invalid_token(self):
        token = "invalid-token"
        self.session.query().filter().first.return_value = None

        with self.assertRaises(HTTPException) as context:
            get_current_user(token, self.session)

        self.assertEqual(context.exception.status_code,
                         status.HTTP_401_UNAUTHORIZED)


if __name__ == "__main__":
    unittest.main()
