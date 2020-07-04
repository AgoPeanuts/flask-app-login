import pytest

from eb import create_app
from eb.models import User, UserOp

class TestUser():
    """
    User Object for the test
    """
    def __init__(self, username, email, plain_password):
        self.username = username
        self.email = email
        self.plain_password = plain_password


@pytest.fixture
def app():
    return create_app('config_test.py')


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def db(app):
    from eb import db

    with app.app_context():
        db.create_all()

        yield db
        db.drop_all()


@pytest.fixture
def create_user(db):
    username = 'test'
    email =  'test@test.com'
    password = 'test-password'

    user = User(username, email)
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    return user


@pytest.fixture
def load_user():
    username = 'test001'
    email = 'test001@test.com'
    password = 'test001-password'

    # Insert user data
    UserOp().add_user(username, email, password)
    test_user = TestUser(username, email, password)

    return test_user

# overwriting the '@app.login_manager.request_loader' to return None if testing with logged in user, the authentication has still alive
@pytest.fixture
def unauthentication(app):
    @app.login_manager.request_loader
    def load_user_from_request(request):
        return None