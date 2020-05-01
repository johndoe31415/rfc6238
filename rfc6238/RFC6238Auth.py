#	rfc6238 - RFC6238-compliant TOTP token generator with Steam Authenticator support
#	Copyright (C) 2020-2020 Johannes Bauer
#
#	This file is part of rfc6238.
#
#	rfc6238 is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	rfc6238 is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with rfc6238; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import time
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.hmac

class RFC6238Presentation():
	def convert(self, int_value):
		raise NotImplementedError(__class__.__name__)

class RFC6238PresentationDigits(RFC6238Presentation):
	def __init__(self, digits):
		assert(isinstance(digits, int))
		assert(1 <= digits <= 8)
		self._digits = digits
		self._modulo = 10 ** digits

	def convert(self, int_value):
		return "%0*d" % (self._digits, int_value % self._modulo)

class RFC6238PresentationSteamAuthenticator(RFC6238Presentation):
	_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"

	def convert(self, int_value):
		code = [ ]
		for i in range(5):
			(int_value, char_index) = divmod(int_value, len(self._ALPHABET))
			code.append(self._ALPHABET[char_index])
		return "".join(code)

class RFC6238Auth():
	def __init__(self, secret, timestep = 30, hmac = "sha1", presentation = RFC6238PresentationDigits(6)):
		assert(isinstance(secret, bytes))
		assert(isinstance(timestep, int))
		assert(isinstance(hmac, str))
		assert(isinstance(presentation, RFC6238Presentation))
		self._secret = secret
		self._timestep = timestep
		self._presentation = presentation

		self._backend = cryptography.hazmat.backends.default_backend()
		self._hash_fnc = {
			"sha1":		cryptography.hazmat.primitives.hashes.SHA1,
			"sha256":	cryptography.hazmat.primitives.hashes.SHA256,
			"sha384":	cryptography.hazmat.primitives.hashes.SHA384,
			"sha512":	cryptography.hazmat.primitives.hashes.SHA512,
		}[hmac.lower()]()

	def code_at(self, ts):
		T = int.to_bytes(ts // self._timestep, length = 8, byteorder = "big")
		hmac = cryptography.hazmat.primitives.hmac.HMAC(self._secret, self._hash_fnc, backend = self._backend)
		hmac.update(T)
		mac = hmac.finalize()

		offset = mac[-1] & 0x0f
		value = int.from_bytes(mac[offset : offset + 4], byteorder = "big") & 0x7fffffff
		return self._presentation.convert(value)

	def now(self):
		t = round(time.time())
		return self.code_at(t)
