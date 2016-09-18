
import re
import sys
import base64
import base58
import datetime

import core.vars
from core.vars import *

from stdnum import imei, imsi, luhn


def is_validCC(number):
	"""
	Check if is a valid CC number
	:param number: number as string
	:return: True or False
	"""
	types = []
	types.append(["Mastercard", [51,52,53,54,55], 16, 19])
	types.append(["Visa", [4], 13, 16])
	types.append(["American Express", [34, 37], 15, 15])
	types.append(["Discover", [6011, range(622126, 622925), range(644,649), 65], 16, 16])
	types.append(["Diners Club - Carte Blanche", [300, 301, 302, 303, 304, 305], 14, 14])
	types.append(["Diners Club - International", [36], 14, 14])
	types.append(["Diners Club - USA & Canada", [54], 16, 16])
	types.append(["InstaPayment", [637, 638, 639], 16, 16])
	types.append(["JCB", [range(3528,3589)], 16, 16])
	types.append(["Laser", [6304, 6706, 6771, 6709], 16, 19])
	types.append(["Maestro", [5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763], 16, 19])
	types.append(["Visa Electron", [4026, 417500, 4508, 4844, 4913, 4917], 16, 16])

	if len(number) < 12:
		return False

	luhn_check = luhn.is_valid(number)
	if not luhn_check:
		return False

	for vend in types:
		for pre in vend[1]:
			if number.startswith(str(pre)) and vend[3] <= len(number) <= vend[4]:
				return True


def special_match(strg, search=re.compile(r'[^\+\-0-9]+').search):
	return not bool(search(strg))


def is_valid_phone(phone):
	return re.match(r'(\+[0-9]+\s*)?(\([0-9]+\))?[\s0-9\-]+[0-9]+', phone)


def too_many_repetitions(number):
	"""
	Disable numbers with more than 4 repeating chars.
	:param number: number as string
	:return: True or False
	"""
	counter = 0
	a = 0
	for char in range(0, len(number)):
		try:
			if number[char] == number[char+1]:
				counter += 1
				if counter == 4:
					return True
			else:
				counter = 0
		except IndexError:
			return False
	return False


def _is_unix_time(string):
	"""
	Try and check is a data is unix-epoch time
	:param string: String input
	:return: True or False
	"""
	try:
		a = datetime.datetime.fromtimestamp(int(string[:10]))
	except:
		return False

	if 2000 <= a.year <= 2050:
		return True
	else:
		return False


def _is_regex_matching(string, regex):
	"""
	Check if a particular string is matching to a regex
	:param string: String input
	:param regex: regex to check against
	:return: True or False
	"""
	try:
		a = re.search(regex, string)
		b = a.group(1)
		return True
	except:
		return False

def _build_search_dict(search_term):
	"""
	Builds a dictionary of search terms the item might
	appear in the data content.
	:param search_term: The string of the search
	:return: dict of search terms
	"""
	retMe = {}
	retMe['plain'] = search_term
	retMe['base64'] = base64.b64encode(search_term)
	retMe['base58'] = base58.b58encode(search_term)
	return retMe


def binary_search(index, string):
	"""
	Search for data in a binary string.
	:param index: The index number in the packet.
	:param string: The binary data to search in.
	:return: List of 2 elements
	"""
	# Todo: Also need to add support for different types of encodings.
	try:
		string = str(string)
	except:
		return OKAY

	# Handle user-based rules:
	if core.vars.config.USER_REQUESTS is not []:
		for t, search, name in core.vars.config.USER_REQUESTS:
			if t == "normal":
				search_dict = _build_search_dict(search)
				for name_i, search_term in search_dict.iteritems():
					if search_term in string:
						return {	"type": name_i,
									"name": name,
									"match": string.find(search_term)
								}

			elif t == "regex":
				if _is_regex_matching(string, search):
					a = re.search(search, string)
					return {	"type": "regex",
								"name": name,
								"match": a.group(1)}

			elif t == "binary":
				if search in string:
					return {	"type": "binary-user",
								"name": name,
								"match": string.find(search)}

			elif t == ("md5sum" or "sha1sum" or "sha256" or "sha512"):
				if search in string:
					return {	"type": name,
								"name": name,
								"match": string.find(search)}
				elif str(search) in str(string):
					return {	"type": name,
								"name": name,
								"match": string.find(search)}

	# In case nothing is found
	return OKAY


def whoami(index, string, field):
	"""
	Checks matches on string
	:param string: string to check
	:return: type
	"""

	# Try to convert data to string or unicode, else, return since
	# we cannot search the data for matching identifiers.
	if type(string) is str or type(string) is unicode:
		pass
	else:
		try:
			string = str(string)
		except:
			return OKAY


	# Here we try to disable false-positives
	if _is_unix_time(string):
		return OKAY


	# Go for the "reliable" information schemes
	if _is_regex_matching(string, IMEI_NOT_REALLY_REGEX):
		b = re.search(IMEI_NOT_REALLY_REGEX, string)
		j = b.group(1)
		a = imei.is_valid(j)
		if a:
			return "IMEI"

	# Sometimes, the stdnum returns a nasty error
	try:
		a = imsi.is_valid(string)
		if a:
			return "IMSI"
	except:
		pass

	a = is_validCC(string)
	if a:
		return "CC"

	if _is_regex_matching(string, SINGLE_COORD):
		return "Longitude"

	if _is_regex_matching(string, SINGLE_COORD):
		return "Latitude"

	if _is_regex_matching(string, COORDINATES):
		return "Coordinate"

	if _is_regex_matching(string, MAC_ADDR):
		return "MAC Address"

	if _is_regex_matching(string, EMAIL):
		return "Email"

	if _is_regex_matching(string, IP_ADDR):
		return "IP Address"


	# Handle user-based rules:
	if core.vars.config.USER_REQUESTS is not []:
		for t, search, name in core.vars.config.USER_REQUESTS:
			if t == "normal":
				if search in string:
					return name

			elif t == "regex":
				if _is_regex_matching(string, search):
					return name

			elif t == "in_field_name":
				if search in field:
					return name

			elif t == "field_name_is":
				if search == field or unicode(search) == field:
					return name


	# Here we put the searches that yield too many false positives
	if FALSE_POSITIVES:
		if special_match(string):
			if 10 <= len(string) <= 18:
				if is_valid_phone(string):
					if string[0] != "-":
						if not too_many_repetitions(string):
							return "MSISDN"

	return OKAY


if __name__ == "__main__":
	sys.stderr.write("This is a module...\n")
	sys.exit(ERR)
