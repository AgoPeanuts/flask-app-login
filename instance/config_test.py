SECRET_KEY='your-test-key'
DEBUG = True

# SQLAlchemy
SQLALCHEMY_DATABASE_URI = 'sqlite:///app_test.db'
SQLALCHEMY_TRACK_MODIFICATIONS = 'False'

# Bcrypt algorithm hashing rounds (reduced for testing purposes only)
BCRYPT_LOG_ROUNDS = 4

# Enable the TESTING flag to disable the error catching during request handling
TESTING = True

# Disable CSRF tokens in the Forms (If it is True, tests don't pass)
WTF_CSRF_ENABLED = False
