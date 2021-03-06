#!/usr/bin/python3
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

import base64
import json
import rfc6238

class Account():
	def __init__(self, account_data):
		self._account_data = account_data

		secret = account_data["secret"]
		if secret.startswith("b64:"):
			secret = base64.b64decode(self._add_padding(account_data["secret"][4:], 4))
		elif secret.startswith("b32:"):
			secret = base64.b32decode(self._add_padding(account_data["secret"][4:].upper(), 8))
		elif secret.startswith("str:"):
			secret = account_data["secret"][4:].encode("ascii")
		else:
			raise NotImplementedError(secret)

		if self._account_data["type"] == "steamauth":
			self._auth = rfc6238.RFC6238Auth(secret, presentation = rfc6238.RFC6238PresentationSteamAuthenticator())
		elif self._account_data["type"] == "rfc6238":
			self._auth = rfc6238.RFC6238Auth(secret, hmac = account_data.get("hmac", "sha1"), presentation = rfc6238.RFC6238PresentationDigits(account_data.get("digits", 6)))
		else:
			raise NotImplementedError(self._account_data["type"])

	@classmethod
	def load_accounts_from_file(cls, json_filename):
		with open(json_filename) as f:
			accounts = json.load(f)
		accounts = [ cls(acct_data) for acct_data in accounts ]
		return accounts

	@staticmethod
	def _add_padding(text, multiple):
		padding = multiple - (len(text) % multiple)
		if padding < multiple:
			text += ("=" * padding)
		return text

	@property
	def name(self):
		return self._account_data["name"]

	@property
	def uri(self):
		return self._auth.uri(name = self.name)

	def _token(self):
		return self._auth.now(return_remaining_validity = True)

	def _split_token(self, token):
		splits = [ ]
		while len(token) > 4:
			next_split = token[:3]
			token = token[3:]
			splits.append(next_split)
		if len(token) > 0:
			splits.append(token)
		return " ".join(splits)

	def print_token(self, token_len = 0):
		(token, remaining_validity) = self._token()
		print("%-*s [%2d]: %-10s %s" % (token_len, self.name, remaining_validity, token, self._split_token(token)))
