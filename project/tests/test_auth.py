# project/tests/test_auth.py

import json

from flask import current_app as app

from project.tests.base import BaseTestCase
from project.tests.utils import add_user, login_user
from project.api.crypto import encode_url_token
from project.api.jwt import revoke_jwt


class TestAuthBlueprint(BaseTestCase):

    def test_no_payload(self):
        """No post data"""
        response = self.client.post(
            '/auth/login')
        data = json.loads(response.data.decode())
        self.assertTrue(data['msg'] == 'Invalid payload.')
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 400)

    def test_no_email(self):
        add_user('test', 'test@test.com', 'testtest')
        """No email """
        response = self.client.post(
            '/auth/login',
            data=json.dumps(dict(
                password='123456'
            )),
            content_type='application/json'
        )
        data = json.loads(response.data.decode())
        self.assertFalse(data['login'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 401)

    def test_no_password(self):
        """No password """
        add_user('test', 'test@test.com', 'testtest')
        response = self.client.post(
            '/auth/login',
            data=json.dumps(dict(
                email='a@b.com'
            )),
            content_type='application/json'
        )
        data = json.loads(response.data.decode())
        self.assertFalse(data['login'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 401)

    def test_invalid_email(self):
        """unknown email """
        add_user('test', 'test@test.com', 'testtest')
        response = self.client.post(
            '/auth/login',
            data=json.dumps(dict(
                email='wrong@wrong.com',
                password='testtest'
            )),
            content_type='application/json'
        )
        data = json.loads(response.data.decode())
        self.assertFalse(data['login'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 401)

    def test_invalid_password(self):
        """Wrong password """
        add_user('test', 'test@test.com', 'testtest')
        response = self.client.post(
            '/auth/login',
            data=json.dumps(dict(
                email='test@test.com',
                password='wrong'
            )),
            content_type='application/json'
        )
        data = json.loads(response.data.decode())
        self.assertFalse(data['login'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 401)

    def test_valid_login(self):
        """Valid login """
        add_user('test', 'test@test.com', 'testtest')
        response = self.client.post(
            '/auth/login',
            data=json.dumps(dict(
                email='test@test.com',
                password='testtest'
            )),
            content_type='application/json'
        )
        data = json.loads(response.data.decode())
        self.assertTrue(data['login'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 200)

    def test_inactive_login(self):
        """Valid login """
        add_user('test', 'test@test.com', 'testtest', active=False)
        response = self.client.post(
            '/auth/login',
            data=json.dumps(dict(
                email='test@test.com',
                password='testtest'
            )),
            content_type='application/json'
        )

        data = json.loads(response.data.decode())
        self.assertFalse(data['login'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 401)

    def test_disabled_login(self):
        """Valid login """
        add_user('test', 'test@test.com', 'testtest', disabled=True)
        response = self.client.post(
            '/auth/login',
            data=json.dumps(dict(
                email='test@test.com',
                password='testtest'
            )),
            content_type='application/json'
        )

        data = json.loads(response.data.decode())
        self.assertFalse(data['login'])
        self.assertTrue(response.content_type == 'application/json')
        self.assertEqual(response.status_code, 401)

    def test_protected_no_auth(self):
        """Protected endpoint, no login """
        with self.client:

            add_user('test', 'test@test.com', 'testtest')

            response = self.client.post(
                '/sanity/protected'
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "Missing cookie \"access_token_cookie\"")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 401)

    def test_protected_with_auth(self):
        """Protected endpoint, with login """
        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post('/sanity/protected', headers={'X-CSRF-TOKEN': access_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'success')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_protected_no_access(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest', refresh_only=True)

            response = self.client.post('/sanity/protected', headers={'X-CSRF-TOKEN': refresh_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "CSRF double submit tokens do not match")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 401)

    def test_logout(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post('/sanity/protected', headers={'X-CSRF-TOKEN': access_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'success')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

            response = self.client.post('/auth/logout', headers={'X-CSRF-TOKEN': access_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['logout'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

            response = self.client.post('/sanity/protected', headers={'X-CSRF-TOKEN': access_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "Missing cookie \"access_token_cookie\"")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 401)

    def test_refresh_no_token(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')

            response = self.client.post('/auth/refresh')

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "Missing cookie \"refresh_token_cookie\"")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 401)

    def test_refresh(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest', refresh_only=True)

            response = self.client.post('/auth/refresh', headers={'X-CSRF-TOKEN': refresh_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['refresh'])
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_blacklist(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post('/sanity/protected', headers={'X-CSRF-TOKEN': access_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'success')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

            revoke_jwt(access_token, app.config['JWT_ACCESS_TOKEN_EXPIRES'] * 1.2)
            response = self.client.post('/sanity/protected', headers={'X-CSRF-TOKEN': access_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'Token has been revoked')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 401)

    def test_claims(self):
        """Load user details from claim """
        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post('/sanity/claim', headers={'X-CSRF-TOKEN': access_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['email'] == 'test@test.com')
            self.assertFalse(data['cbl_member'])
            self.assertTrue(data['username'] == 'test')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_change_password_no_auth(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')

            response = self.client.post('/auth/changepassword')

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "Missing cookie \"access_token_cookie\"")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 401)

    def test_change_password(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post(
                '/auth/changepassword',
                data=json.dumps(dict(
                    old_password='testtest',
                    new_password='testtestabc'
                )),
                content_type='application/json',
                headers={'X-CSRF-TOKEN': access_csrf}
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data["msg"] == "Password changed successfully")

            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='test@test.com',
                    password='testtestabc'
                )),
                content_type='application/json'
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['login'])

    def test_change_password_wrong_old(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post('/auth/changepassword', headers={'X-CSRF-TOKEN': access_csrf})

            response = self.client.post(
                '/auth/changepassword',
                data=json.dumps(dict(
                    old_password='wrongwrong',
                    new_password='testtestabc'
                )),
                content_type='application/json',
                headers={'X-CSRF-TOKEN': access_csrf}
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'Incorrect password')

            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='test@test.com',
                    password='testtestabc'
                )),
                content_type='application/json'
            )

            data = json.loads(response.data.decode())
            self.assertFalse(data['login'])

    def test_reset_password_get(self):

        with self.client:

            user = add_user('test', 'test@test.com', 'testtest')
            token = encode_url_token('password', user.email)

            url = 'auth/resetpassword?id={}'.format(token)
            response = self.client.get(url)

            data = json.loads(response.data.decode())
            self.assertTrue(data['token'] == token)

    def test_reset_password_email_mismatch(self):

        with self.client:

            user = add_user('test', 'test@test.com', 'testtest')
            token = encode_url_token('password', user.email)

            url = 'auth/resetpassword?id={}'.format(token)

            response = self.client.post(
                url,
                data=json.dumps(dict(
                    email='test1@test.com',
                    password='test'
                )),
                content_type='application/json'
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'email mismatch')

    def test_reset_password_change(self):

        with self.client:

            user = add_user('test', 'test@test.com', 'testtest')
            token = encode_url_token('password', user.email)

            url = 'auth/resetpassword?id={}'.format(token)

            response = self.client.post(
                url,
                data=json.dumps(dict(
                    email='test@test.com',
                    password='testtestabc'
                )),
                content_type='application/json'
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'Password changed successfully')

            response = self.client.post(
                '/auth/login',
                data=json.dumps(dict(
                    email='test@test.com',
                    password='testtestabc'
                )),
                content_type='application/json'
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['login'])

    def test_invite_no_auth(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')

            response = self.client.post(
                '/auth/createinvite',
                data=json.dumps(dict(
                    email='example@example.com',
                    name='example'
                )),
                content_type='application/json'
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "Missing cookie \"access_token_cookie\"")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 401)

    def test_invite_not_cbl(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest')
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post(
                '/auth/createinvite',
                data=json.dumps(dict(
                    email='example@example.com',
                    name='example'
                )),
                content_type='application/json',
                headers={'X-CSRF-TOKEN': access_csrf}
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "Core CBL members only")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 403)

    def test_invite_new(self):

        with self.client:

            add_user('test', 'test@test.com', 'testtest', cbl_member=True)
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post(
                '/auth/createinvite',
                data=json.dumps(dict(
                    email='example@example.com',
                    name='example',
                    suppress_email=True
                )),
                content_type='application/json',
                headers={'X-CSRF-TOKEN': access_csrf}
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "Invite sent")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_invite_existing_ok(self):

        with self.client:

            add_user('existing', 'existing@existing.com', 'existingexisting', active=False)
            add_user('test', 'test@test.com', 'testtest', cbl_member=True)
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post(
                '/auth/createinvite',
                data=json.dumps(dict(
                    email='existing@existing.com',
                    name='existing',
                    suppress_email=True
                )),
                content_type='application/json',
                headers={'X-CSRF-TOKEN': access_csrf}
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "Invite sent")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_invite_existing_disabled(self):

        with self.client:

            add_user('existing', 'existing@existing.com', 'existingexisting', active=False, disabled=True)
            add_user('test', 'test@test.com', 'testtest', cbl_member=True)
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post(
                '/auth/createinvite',
                data=json.dumps(dict(
                    email='existing@existing.com',
                    name='existing',
                    suppress_email=True
                )),
                content_type='application/json',
                headers={'X-CSRF-TOKEN': access_csrf}
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "User banned!")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 403)

    def test_invite_existing_active(self):

        with self.client:

            add_user('existing', 'existing@existing.com', 'existingexisting', active=True, disabled=False)
            add_user('test', 'test@test.com', 'testtest', cbl_member=True)
            access_csrf, refresh_csrf, access_token = login_user(self.client, 'test@test.com', 'testtest')

            response = self.client.post(
                '/auth/createinvite',
                data=json.dumps(dict(
                    email='existing@existing.com',
                    name='existing',
                    suppress_email=True
                )),
                content_type='application/json',
                headers={'X-CSRF-TOKEN': access_csrf}
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == "User already exists")
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 409)

    def test_activate_ok(self):

        with self.client:

            add_user('existing', 'existing@existing.com', 'existingexisting', active=False)
            add_user('test', 'test@test.com', 'testtest', cbl_member=True)

            token = encode_url_token('invite', 'existing@existing.com')

            url = 'auth/activate?id={}'.format(token)

            response = self.client.post(
                url,
                data=json.dumps(dict(
                    email='existing@existing.com',
                    username='existing',
                    password='testtest'
                )),
                content_type='application/json'
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'Account activated')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

            access_csrf, refresh_csrf, access_token = login_user(self.client, 'existing@existing.com', 'testtest')

            response = self.client.post('/sanity/protected', headers={'X-CSRF-TOKEN': access_csrf})

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'success')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 200)

    def test_activate_duplicate_username(self):

        with self.client:

            add_user('existing', 'existing@existing.com', 'existingexisting', active=False)
            add_user('test', 'test@test.com', 'testtest', cbl_member=True)

            token = encode_url_token('invite', 'existing@existing.com')

            url = 'auth/activate?id={}'.format(token)

            response = self.client.post(
                url,
                data=json.dumps(dict(
                    email='existing@existing.com',
                    username='test',
                    password='testtest'
                )),
                content_type='application/json'
            )

            data = json.loads(response.data.decode())
            self.assertTrue(data['msg'] == 'Username already in use')
            self.assertTrue(response.content_type == 'application/json')
            self.assertEqual(response.status_code, 400)
