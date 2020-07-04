SECRET_KEY='eventbuilder-test-key'
DEBUG = True

# SQLAlchemy
SQLALCHEMY_DATABASE_URI = 'sqlite:///eb_test.db'
SQLALCHEMY_TRACK_MODIFICATIONS = 'False'

# Bcrypt algorithm hashing rounds (reduced for testing purposes only!)
BCRYPT_LOG_ROUNDS = 4

# Enable the TESTING flag to disable the error catching during request handling
# so that you get better error reports when performing test requests against the application.
TESTING = True

# Disable CSRF tokens in the Forms (only valid for testing purposes!)
WTF_CSRF_ENABLED = False