SECRET_KEY='your-secret-key'
WTF_CSRF_ENABLED = True
DEBUG = True

# SQLAlchemy
SQLALCHEMY_DATABASE_URI = 'sqlite:///eb.db'
SQLALCHEMY_TRACK_MODIFICATIONS = 'False'

# Bcrypt algorithm hashing rounds
BCRYPT_LOG_ROUNDS = 15
