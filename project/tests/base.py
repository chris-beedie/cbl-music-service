# project/tests/base.py


from flask_testing import TestCase

from project import create_app, db

app = create_app()


class BaseTestCase(TestCase):
    def create_app(self):
        app.config.from_object('project.config.TestingConfig')
        return app

    def setUp(self):
        self.client.cookies = None
        db.create_all()
        db.session.commit()

    def tearDown(self):
        self.client.cookies = None
        db.session.remove()
        db.drop_all()
