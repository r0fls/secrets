import unittest
import secrets

class TestEncryptDecrypt(unittest.TestCase):
    def test_encrypt_decrypt(self):
        keys = secrets.generate_keys()
        public = keys["public"]
        private = keys["private"]
        self.assertEqual(secrets.decrypt(secrets.encrypt('foo', public),
                                         private), 'foo')


if __name__ == '__main__':
    unittest.main()
