from eb import db, login_manager, bcrypt
from flask_login import UserMixin
from datetime import datetime


# User Class with UserMixin
class User(db.Model, UserMixin):

    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.LargeBinary(60), nullable=False)
    created = db.Column(db.DateTime, default=datetime.now)
    updated = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def set_password(self, plaintext_password):
        """
        The plaine password is hashed and set to password of User Object
        """
        self.password = bcrypt.generate_password_hash(plaintext_password)

    def is_correct_password(self, password):
        """
        Check password for login
        """
        return bcrypt.check_password_hash(self.password, password)

    def __repr__(self):
        return '<User id={}, username={}, email={}, created={}>'.format(self.id, self.username, self.email, self.created)

class UserOp:
    """
    User class manipulation interface
    """
    def get_user_id(self, id):
        user = User.query.get(id)
        return user

    def get_user_email(self, email):
        user = User.query.filter_by(email=email).first()
        return user

    def get_user_name(self, username):
        user = User.query.filter_by(username=username).first()
        return user

    def add_user(self, username, email, password):
        new_user = User(username, email)
        # Call password setter
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

    def update_user(self, user):
        db.session.add(user)
        db.session.commit()

    def delete_user(self, user):
        db.session.delete(user)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
