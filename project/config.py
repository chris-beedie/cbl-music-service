# project/config.py


import os


class BaseConfig:
    """Base configuration"""
    DEBUG = False
    TESTING = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SALT = os.environ.get('SALT')
    BCRYPT_LOG_ROUNDS = 13

    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_SESSION_COOKIE = False
    JWT_CSRF_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    MAILGUN_KEY = os.environ.get('MAILGUN_KEY')
    MAILGUN_URL = os.environ.get('MAILGUN_URL')
    MAILGUN_FROM = os.environ.get('MAILGUN_FROM')

    BASE_URL = os.environ.get('BASE_URL')
    PASSWORD_MIN_LEN = 8


class DevelopmentConfig(BaseConfig):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    BCRYPT_LOG_ROUNDS = 4
    JWT_COOKIE_SECURE = False

class TestingConfig(BaseConfig):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_TEST_URL')
    BCRYPT_LOG_ROUNDS = 4
    JWT_COOKIE_SECURE = False
    # JWT_SESSION_COOKIE = False

class ProductionConfig(BaseConfig):
    """Production configuration"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
