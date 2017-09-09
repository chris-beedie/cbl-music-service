# project/tests/test_users.py


import json
from project.tests.base import BaseTestCase


class TestSanity(BaseTestCase):

    def test_endpoint(self):
        """Ensure the /ping route behaves correctly."""
        response = self.client.get('/sanity/ping')
        data = json.loads(response.data.decode())
        self.assertEqual(response.status_code, 200)
        self.assertIn('pong!', data['message'])
        self.assertIn('success', data['status'])
