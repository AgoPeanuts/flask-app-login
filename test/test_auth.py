import pytest
from eb import create_app
from eb.models import User, UserOp


username = 'user-test01234567890'
email = 'user-test@gmail.com'
password = 'user-test-password'

"""
the unit tests for the auth/models.py
"""
def test_new_user():
    """
    GIVEN a User model
    WHEN a new User is created
    THEN check the username and email are defined correctly
    """
    user = User(username, email)
    assert user.username == username
    assert user.email == email
    assert user.password is None

def test_set_password():
    """
    GIVEN a User model
    WHEN set_password is called
    THEN check the user object has hashed password
    """
    user = User(username, email)
    user.set_password(password)

    assert user.username == username
    assert user.email == email
    assert user.password is not None
    assert user.password != password

def test_is_correct_password():
    """
    GIVEN a User model
    WHEN is_correct_password is called
    THEN check the plaintext password and hashed password matches and invalid plaintext password doesn't match
    """
    user = User(username, email)
    user.set_password(password)

    assert user.password != password
    assert user.is_correct_password(password)
    invalid_password = password + '1'
    assert not user.is_correct_password(invalid_password)

def test_get_user_id(db, create_user):
    """
    GIVEN a UserOp model and an existing User
    WHEN get_user_id is called
    THEN check the user are returned correctly
    """
    user = UserOp().get_user_id(create_user.id)

    assert user.username == create_user.username
    assert user.email == create_user.email
    assert user.password == create_user.password
    assert user.created == create_user.created
    assert user.updated == create_user.updated

    invalid_id = create_user.id + 1
    user = UserOp().get_user_id(invalid_id)

    assert invalid_id != create_user.id
    assert user is None

def test_get_user_email(db, create_user):
    """
    GIVEN a UserOp model and an existing User
    WHEN get_user_email is called
    THEN check the user are returned correctly
    """
    user = UserOp().get_user_email(create_user.email)

    assert user.id == create_user.id
    assert user.username == create_user.username
    assert user.password == create_user.password
    assert user.created == create_user.created
    assert user.updated == create_user.updated

    invalid_email = create_user.email + '1'
    user = UserOp().get_user_email(invalid_email)

    assert invalid_email != create_user.email
    assert user is None

def test_get_user_name(db, create_user):
    """
    GIVEN a UserOp model and an existing User
    WHEN get_user_name is called
    THEN check the user are returned correctly
    """
    user = UserOp().get_user_name(create_user.username)

    assert user.id == create_user.id
    assert user.email == create_user.email
    assert user.password == create_user.password
    assert user.created == create_user.created
    assert user.updated == create_user.updated

    invalid_username = create_user.username + 'a'
    user = UserOp().get_user_name(invalid_username)

    assert invalid_username != create_user.username
    assert user is None

def test_add_user(db):
    """
    GIVEN a UserOp model
    WHEN a new User is created
    THEN check the user are stored correctly
    """
    UserOp().add_user(username, email, password)

    # get a user by email
    user = User.query.filter_by(email=email).first()

    assert user.id == 1
    assert user.username == username
    assert user.email == email
    assert user.password != password
    assert user.is_correct_password(password)

def test_update_user(db, create_user):
    """
    GIVEN a UserOp model and an existing User
    WHEN the User is update
    THEN check the user data are stored (updated) correctly
    """
    user_id = create_user.id
    old_username = create_user.username
    old_created = create_user.created
    old_updated = create_user.updated

    create_user.username = username
    create_user.email = email
    create_user.set_password(password)

    # update the user
    UserOp().update_user(create_user)

    user = User.query.get(user_id)
    assert user.username != old_username
    assert user.username == username
    assert user.email == email
    assert user.is_correct_password(password)
    assert user.created == old_created
    assert user.updated != old_updated

    user = User.query.filter_by(username=old_username).first()
    assert user is None

def test_delete_user(db, create_user):
    """
    GIVEN a UserOp model and an existing User
    WHEN the User is deleted
    THEN check the user doesn't exist
    """
    user_id = create_user.id
    UserOp().delete_user(create_user)

    assert User.query.get(user_id) is None


"""
the function tests for the mod_auth
"""
def test_view_page_authentication(app, client, create_user):
    """
    WHEN the Index page, Change Password, and Delete account is requested (GET) with logged in user
    THEN check the response is valid
    """
    with app.test_request_context():
        test_user = User.query.get(create_user.id)

        @app.login_manager.request_loader
        def load_user_from_request(request):
            return test_user

        resp = client.get('/auth/change', follow_redirects=True)
        assert resp.status_code == 200
        assert b'Change your password' in resp.data
        assert test_user.username.encode() in resp.data
        assert test_user.is_authenticated == True

        resp = client.get('/auth/delete', follow_redirects=True)
        assert resp.status_code == 200
        assert b'Delete your account' in resp.data
        assert test_user.username.encode() in resp.data
        assert test_user.is_authenticated == True

        resp = client.get('/', follow_redirects=True)
        assert resp.status_code == 200
        assert b'Index' in resp.data
        assert test_user.username.encode() in resp.data
        assert test_user.is_authenticated == True


def test_view_page_non_authentication(app, client, unauthentication):
    """
    WHEN the login, register, Change Password, Delete account, and Index page is requested (GET) without login
    THEN check the response is valid and Change Password, Delete account page, and Index need login_required so check the redirect to /login
    """
    response = client.get('/auth/login')
    assert response.status_code == 200
    assert b'Login' in response.data

    response = client.get('/auth/register')
    assert response.status_code == 200
    assert b'Sign Up' in response.data

    # Check the final path after redirects
    from flask import request, url_for
    with app.test_client() as client:
        response = client.get('/auth/change', follow_redirects=True)

        assert request.args.get('next') == url_for('auth.change')
        assert request.path == url_for('auth.login')
        assert response.status_code == 200
        assert b'Login' in response.data

        res = client.get('/auth/delete', follow_redirects=True)

        assert request.args.get('next') == url_for('auth.delete')
        assert request.path == url_for('auth.login')
        assert res.status_code == 200
        assert b'Login' in response.data

        response = client.get('/', follow_redirects=True)

        assert request.args.get('next') == url_for('main.index')
        assert request.path == url_for('auth.login')
        assert response.status_code == 200
        assert b'Login' in response.data


def test_valid_login_logout(client, db, load_user):
    """
    GIVEN an existence user
    WHEN the '/login' page is requested (POST) with valid user data
    THEN check the response is valid and go to the main/index page
    """
    response = client.post('/auth/login',
                                data=dict(email=load_user.email, password=load_user.plain_password),
                                follow_redirects=True)

    assert response.status_code == 200
    assert load_user.username.encode() in response.data
    assert b"Index" in response.data

    """
    WHEN the '/logout' page is requested (GET)
    THEN check the response is valid and return to the login page
    """
    response = client.get('/auth/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b"Logged out!" in response.data
    assert b"Login" in response.data
    assert not load_user.username.encode() in response.data


@pytest.mark.parametrize(
    ('email', 'password', 'message'), (
    ('test001@test.com', 'test001', b'Incorrect password.'),
    ('test@test.com', 'test001-password', b'Incorrect email.'),
    ('', 'test001-password', b'Email is required.'),
    ('test001@test.com', '', b'Password is required.'),
    ('a', 'test001-password', b'Invalid email address.')
))
def test_invalid_login(client, db, load_user, email, password, message):
    """
    WHEN the '/login' page is requested with invalid data (POST)
    THEN check an error message is returned to the user
    """
    response = client.post(
        '/auth/login',
        data=dict(email=email, password=password),
        follow_redirects=True)

    assert response.status_code == 200
    assert message in response.data


def test_valid_registre(client, db):
    """
    WHEN the '/register' page is requested with valid data (POST)
    THEN check the response is valid and the user can login
    """

    response = client.post('auth/register',
                                data=dict(username=username, email=email, password=password, confirm_password=password),
                                follow_redirects=True)

    assert response.status_code == 200
    assert b'Your account has been created!' in response.data
    assert b"Login" in response.data

    response = client.post('/auth/login',
                            data=dict(email=email, password=password),
                            follow_redirects=True)

    assert response.status_code == 200
    assert username.encode() in response.data
    assert b"Index" in response.data


@pytest.mark.parametrize(
    ('username', 'email', 'password', 'confirm_password', 'message'), (
    ('test001', email, password, password, b'The username has already existed.'),
    (username, 'test001@test.com', password, password, b'The email has already existed.'),
    (username, email, password, '12345', b'Field must be equal to password.'),
    (username, email, '12345', password, b'Field must be at least 6 characters long.'),
    ('', email, password, password, b'Username is required.'),
    (username, '', password, password, b'Email is required.'),
    (username, email, '', password, b'Password is required.'),
    (username, email, password, '',  b'Confirm Password is required.'),
    (username, 'test002@', password, password, b'Invalid email address.'),
    ('a', email, password, password, b'Field must be between 2 and 20 characters long.'),
    ('a12345678901234567890', email, password, password, b'Field must be between 2 and 20 characters long.')
))
def test_invalid_registre(client, db, load_user, username, email, password, confirm_password, message):
    """
    WHEN the '/register' page is requested with invalid data (POST)
    THEN check an error message is returned to the user
    """

    response = client.post('/auth/register',
                            data=dict(username=username, email=email, password=password, confirm_password=confirm_password),
                            follow_redirects=True)

    assert response.status_code == 200
    assert message in response.data


def test_change_password(app, client, db, load_user):
    """
    WHEN the '/change' page is requested by logged in user with invalid and valid data (POST)
    THEN check an error and success message is returned and the user can login with new password
    """
    original_password = load_user.plain_password

    with app.test_request_context():
        test_user = User.query.filter_by(email=load_user.email).first()

        @app.login_manager.request_loader
        def load_user_from_request(request):
            return test_user

    invalid_password = '12345'
    new_password = original_password + 'a'

    # fail with invalid password
    response = client.post('/auth/change',
                            data=dict(password=original_password, new_password=invalid_password, confirm_new_password=new_password))

    assert response.status_code == 200
    assert b'Field must be at least 6 characters long.' in response.data
    assert b'Field must be equal to new password.' in response.data
    assert b"Change your password" in response.data

    # fail with incorrect password
    response = client.post('/auth/change',
                        data=dict(password=new_password, new_password=new_password, confirm_new_password=new_password))

    assert response.status_code == 200
    assert b'Incorrect password.' in response.data
    assert b"Change your password" in response.data

    # success
    response = client.post('/auth/change',
                            data=dict(password=original_password, new_password=new_password, confirm_new_password=new_password))

    assert response.status_code == 200
    assert b'Your password has been changed!' in response.data
    assert b"Change your password" in response.data

    # log out
    client.get('/auth/logout', follow_redirects=True)

    # log in with original password
    response = client.post('/auth/login',
                            data=dict(email=load_user.email, password=original_password))

    assert response.status_code == 200
    assert b"Login" in response.data

    # log in with new password
    response = client.post('/auth/login',
                            data=dict(email=load_user.email, password=new_password),
                            follow_redirects=True)

    assert response.status_code == 200
    assert load_user.username.encode() in response.data
    assert b"Index" in response.data


def test_delete_account(app, client, db, load_user):
    """
    WHEN the '/delete' page is requested (POST) by logged in user
    THEN check an success message is returned and the user can not login
    """
    original_email = load_user.email
    original_password = load_user.plain_password

    with app.test_request_context():
        test_user = User.query.filter_by(email=load_user.email).first()

        @app.login_manager.request_loader
        def load_user_from_request(request):
            return test_user

    response = client.post('auth/delete', follow_redirects=True)

    assert response.status_code == 200
    assert b'Your account has been deleted.' in response.data
    assert b'Sign Up' in response.data

    # login
    response = client.post('/auth/login',
                            data=dict(email=original_email, password=original_password),
                            follow_redirects=True)

    assert response.status_code == 200
    assert b'Incorrect email.' in response.data
    assert b"Login" in response.data
