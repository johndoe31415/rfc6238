import unittest

from rfc6238 import RFC6238Auth, RFC6238PresentationDigits, RFC6238PresentationSteamAuthenticator

class TOTPTests(unittest.TestCase):
	def test_rfc6238_testvectors_sha1(self):
		secret = b"12345678901234567890"
		auth = RFC6238Auth(secret = secret, presentation = RFC6238PresentationDigits(8))
		self.assertEqual(auth.code_at(59), "94287082")
		self.assertEqual(auth.code_at(1111111109), "07081804")
		self.assertEqual(auth.code_at(1111111111), "14050471")
		self.assertEqual(auth.code_at(1234567890), "89005924")
		self.assertEqual(auth.code_at(2000000000), "69279037")
		self.assertEqual(auth.code_at(20000000000), "65353130")
		self.assertEqual(auth.code_at(96262), "00044814")

	def test_rfc6238_testvectors_sha256(self):
		secret = b"12345678901234567890123456789012"
		auth = RFC6238Auth(secret = secret, hmac = "sha256", presentation = RFC6238PresentationDigits(8))
		self.assertEqual(auth.code_at(59), "46119246")
		self.assertEqual(auth.code_at(1111111109), "68084774")
		self.assertEqual(auth.code_at(1111111111), "67062674")
		self.assertEqual(auth.code_at(1234567890), "91819424")
		self.assertEqual(auth.code_at(2000000000), "90698825")
		self.assertEqual(auth.code_at(20000000000), "77737706")

	def test_rfc6238_testvectors_sha512(self):
		secret = b"1234567890123456789012345678901234567890123456789012345678901234"
		auth = RFC6238Auth(secret = secret, hmac = "sha512", presentation = RFC6238PresentationDigits(8))
		self.assertEqual(auth.code_at(59), "90693936")
		self.assertEqual(auth.code_at(1111111109), "25091201")
		self.assertEqual(auth.code_at(1111111111), "99943326")
		self.assertEqual(auth.code_at(1234567890), "93441116")
		self.assertEqual(auth.code_at(2000000000), "38618901")
		self.assertEqual(auth.code_at(20000000000), "47863826")

	def test_vanilla(self):
		# Vector from RFC4226 Sect. 5.3
		auth = RFC6238Auth(b"12345678901234567890")
		self.assertEqual(auth.code_at(0), "755224")

	def test_steam(self):
		secret = b"this is a test"
		auth = RFC6238Auth(secret = secret, presentation = RFC6238PresentationSteamAuthenticator())
		self.assertEqual(auth.code_at(57775080), "R3333")

	def test_uri_steam(self):
		with self.assertRaises(NotImplementedError):
			RFC6238Auth(secret = b"foo", presentation = RFC6238PresentationSteamAuthenticator()).uri()

	def test_uri_rfc6238(self):
		secret = b"!!!"
		self.assertEqual(RFC6238Auth(secret = secret, presentation = RFC6238PresentationDigits(6)).uri(name = "Foobar"), "otpauth://totp/Foobar?secret=EEQSC")
		self.assertEqual(RFC6238Auth(secret = secret, presentation = RFC6238PresentationDigits(6)).uri(name = "Foobar 123"), "otpauth://totp/Foobar%20123?secret=EEQSC")
		self.assertEqual(RFC6238Auth(secret = secret, presentation = RFC6238PresentationDigits(7)).uri(name = "Foobar"), "otpauth://totp/Foobar?secret=EEQSC&digits=7")
		self.assertEqual(RFC6238Auth(secret = secret, hmac = "sha256", presentation = RFC6238PresentationDigits(5)).uri(name = "Foobar"), "otpauth://totp/Foobar?secret=EEQSC&algorithm=SHA256&digits=5")
