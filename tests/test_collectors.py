import unittest
from modules.collectors import check_cnic, check_email, check_phone, check_username
class CollectorTests(unittest.TestCase):
    def test_cnic_format(self):
        self.assertTrue(check_cnic('12345-1234567-1')['format_has_13_digits'])
        self.assertFalse(check_cnic('123')['format_has_13_digits'])
    def test_email_syntax(self):
        self.assertTrue(check_email('test@example.com')['syntax_valid'])
        self.assertFalse(check_email('not-an-email')['syntax_valid'])
    def test_phone_length(self):
        self.assertTrue(check_phone('+923001234567')['is_plausible_international_length'])
        self.assertFalse(check_phone('12')['is_plausible_international_length'])
    def test_username_validation(self):
        self.assertEqual(check_username('../bad', ['GitHub'])[0]['status'], 'invalid_input')
if __name__ == '__main__': unittest.main()
