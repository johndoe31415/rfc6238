import unittest

from rfc6238 import RFC6238Auth, RFC6238PresentationDigits, RFC6238PresentationSteamAuthenticator

class TOTPTests(unittest.TestCase):
	def test_rfc6238_testvectors_sha1(self):
		secret = b"12345678901234567890"
		auth = RFC6238Auth(secret = secret, presentation = RFC6238PresentationDigits(8))
		self.assertEqual(auth.at_ts(59), "94287082")
		self.assertEqual(auth.at_ts(1111111109), "07081804")
		self.assertEqual(auth.at_ts(1111111111), "14050471")
		self.assertEqual(auth.at_ts(1234567890), "89005924")
		self.assertEqual(auth.at_ts(2000000000), "69279037")
		self.assertEqual(auth.at_ts(20000000000), "65353130")

	def test_rfc6238_testvectors_sha256(self):
		secret = b"12345678901234567890123456789012"
		auth = RFC6238Auth(secret = secret, hmac = "sha256", presentation = RFC6238PresentationDigits(8))
		self.assertEqual(auth.at_ts(59), "46119246")
		self.assertEqual(auth.at_ts(1111111109), "68084774")
		self.assertEqual(auth.at_ts(1111111111), "67062674")
		self.assertEqual(auth.at_ts(1234567890), "91819424")
		self.assertEqual(auth.at_ts(2000000000), "90698825")
		self.assertEqual(auth.at_ts(20000000000), "77737706")

	def test_rfc6238_testvectors_sha512(self):
		secret = b"1234567890123456789012345678901234567890123456789012345678901234"
		auth = RFC6238Auth(secret = secret, hmac = "sha512", presentation = RFC6238PresentationDigits(8))
		self.assertEqual(auth.at_ts(59), "90693936")
		self.assertEqual(auth.at_ts(1111111109), "25091201")
		self.assertEqual(auth.at_ts(1111111111), "99943326")
		self.assertEqual(auth.at_ts(1234567890), "93441116")
		self.assertEqual(auth.at_ts(2000000000), "38618901")
		self.assertEqual(auth.at_ts(20000000000), "47863826")

	def test_vanilla(self):
		# Vector from RFC4226 Sect. 5.3
		auth = RFC6238Auth(b"12345678901234567890")
		self.assertEqual(auth.at_ts(0), "755224")

	def test_steam(self):
		secret = b"12345678901234567890"
		auth = RFC6238Auth(secret = secret, presentation = RFC6238PresentationSteamAuthenticator())
		print(auth.at_ts(0))
