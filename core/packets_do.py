import time
import json
import config
import base64
import urllib
import binascii
from core.vars import *
from scapy.all import *
from core.tester import *
import core.vars

try:
	# This import works from the project directory
	import scapy_http.http as http
except ImportError:
	# If you installed this package via pip, you just need to execute this
	from scapy.layers import http as http


def _is_base64(s):
	"""
	Checks if the data is Base64 encoded
	:param s: string to check
	:return: decoded data or False
	"""
	if type(s) is not str or unicode:
		return False
	s = ''.join([s.strip() for s in s.split("\n")])
	try:
		enc = base64.b64encode(base64.b64decode(s)).strip()
		return enc == s
	except TypeError:
		return False
	except UnicodeEncodeError:
		return False


def _is_json(myjson):
	"""
	Tests to see if the data is JSON format
	:param myjson: String which might be JSON
	:return: Boolean
	"""
	if "{" in myjson and "}" in myjson:
		pass
	else:
		return False
	try:
		json_object = json.loads(myjson)
	except ValueError, e:
		return False
	return True


class HandlePacket():
	"""
	General packet handler.
	Currently only works on HTTP Requests.
	"""
	def __init__(self, index, packet):
		self.index = index				# Index of packet within PCAP
		self.raw_packet = packet		# The Actual packet
		self.time = None				# Time stamp of the packet
		self.host = None				# Host name the packet it sent to
		self.path = None				# Full URI (if available)
		self.payload = None				# Actual content of request
		self.binary_data = [] 			# Actual binary data
		self.binary_flag = False		# Binary flag is set if the data is not
										# an HTTP request
		self.content_type = None		# The type of the content
		self.request_method = None		# The request method
		self.marked_fields = []			# Fields which might match
		self.get_parameters = []		# A list of GET parameters
		self.post_parameters = []		# A list of POST Parameters

		self._isHTTPRequest()			# Check if this is an HTTP request

		# If the packet is an HTTP request, do the self._CheckFields on it
		if self.request_method == "GET" or self.request_method == "POST":
			self._CheckFields()			# Validate fields.

		# If it is not, try the binary search for the given data types
		else:
			self.binary_flag = True
			self._SearchBinaryData()


	def _AnalyzeGetLine(self, line):
		"""
		Analyze the GET request line and split it to parameters
		:param line: The string of the line.
		:return: Boolean
		"""

		# Check if there is a "?" in the path.
		# If not it's probably not parametized.
		if line.find("?") == -1:
			return False

		params = line[line.find("?") + 1:]
		params = params.split("&")
		ret_gets = []
		for i in params:
			self.get_parameters.append(i.split("="))

		return True


	def _AnalyzePostBody(self, body):
		"""
		Analyze the POST request line and split it to parameters
		:param body: The string body of the POST request.
		:return: Boolean
		"""

		# First, check if the entire content is JSON:
		if _is_json(body):
			# Is JSON
			a = json.loads(body)
			if type(a) is dict:
				for key, value in json.loads(body).iteritems():
					self.post_parameters.append([key, value])
			elif type(a) is list:
				try:
					for key, value in a:
						self.post_parameters.append([key, value])
				except ValueError:
					# It's more or less than 2 values so we don't know how to handle it.
					pass

		# If not JSON, try splitting and check if JSON
		else:
			params = body[body.find("?") + 1:]
			params = params.split("&")
			for i in params:
				try:
					key, val = i.split("=")
					if _is_json(val):
						self.post_parameters.append([key + "-JSON", val])
						a = json.loads(val)
						if type(a) is list:
							for k, v in a:
								self.post_parameters.append(["%s:%s" %(key, k), v])
						elif type(a) is dict:
							for k, v in a.iteritems():
								self.post_parameters.append(["%s:%s" %(key, k), v])

				except ValueError:
					self.post_parameters.append(i.split("="))
		return True


	def _isHTTPRequest(self):
		"""
		If the packet is an HTTPRequest, try to extract the fields in them.
		:return: Null
		"""

		if self.raw_packet.haslayer(http.HTTPRequest):

			if self.raw_packet[http.HTTPRequest].getfieldval('Method') == "GET":

				if "?" in self.raw_packet[http.HTTPRequest].getfieldval('Path'):
					# Get Header Details
					self.request_method = "GET"
					self.host = self.raw_packet[http.HTTPRequest].getfieldval('Host')
					self.path = self.raw_packet[http.HTTPRequest].getfieldval('Path')
					self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.raw_packet.time))

					temp_get = urllib.unquote_plus(self.raw_packet[http.HTTPRequest].getfieldval('Path'))
					self._AnalyzeGetLine(temp_get)

					core.vars.config.PACKETS.append(self)

				else:
					# Non parameterized GET
					pass

			elif self.raw_packet[http.HTTPRequest].getfieldval('Method') == "POST":

				# Get Header Details
				self.request_method = "POST"
				self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.raw_packet.time))
				self.host = self.raw_packet[http.HTTPRequest].getfieldval('Host')
				self.path = self.raw_packet[http.HTTPRequest].getfieldval('Path')

				self.content_type = self.raw_packet[http.HTTPRequest].getfieldval('Content-Type')
				self.payload = self.raw_packet[http.HTTPRequest].payload

				# Get GET Parameters
				temp_get = urllib.unquote_plus(str(self.raw_packet[http.HTTPRequest].getfieldval('Path')))
				self._AnalyzeGetLine(temp_get)

				# Get POST Parameters
				temp_get = str(self.raw_packet[http.HTTPRequest].payload)
				temp_get = urllib.unquote_plus(temp_get)

				self._AnalyzePostBody(temp_get)

				core.vars.config.PACKETS.append(self)

			else:
				pass  # print self.raw_packet[http.HTTPRequest].getfieldval('Method')

		elif "GET " in str(self.raw_packet.original) and "Host: " in str(self.raw_packet.original) and "HTTP/1. " in str(self.raw_packet.original):

			self.request_method = "GET"
			semi = self.raw_packet.original[self.raw_packet.original.find("GET "):].split("\r\n")
			self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.raw_packet.time))
			for item in semi:
				if ("GET " or "POST ") in item:
					self.request_method = item[:item.find(" ")]
					self.path = urllib.unquote_plus(item[item.find(self.request_method)+len(self.request_method):item.find(" HTTP/1.")])
				else:
					try:
						key, value = item.split(": ")
						if key == "Host":
							self.host = value
					except:
						pass

			temp_get = urllib.unquote_plus(self.path)
			_AnalyzeGetLine(temp_get)

			core.vars.config.PACKETS.append(self)

		elif "POST " in str(self.raw_packet.original) and "Host: " in str(self.raw_packet.original) and "HTTP/1. " in str(self.raw_packet.original):

			self.request_method = "POST"
			semi = self.raw_packet.original[self.raw_packet.original.find("POST "):].split("\r\n")
			self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.raw_packet.time))
			for item in semi:
				if ("GET " or "POST ") in item:
					self.request_method = item[:item.find(" ")]
					self.path = urllib.unquote_plus(item[item.find(self.request_method) + len(self.request_method):item.find(" HTTP/1.")])
				else:
					try:
						key, value = item.split(": ")
						if key == "Host":
							self.host = value
					except:
						pass

			# GET Parameters
			temp_get = urllib.unquote_plus(self.path)
			self._AnalyzeGetLine(temp_get)

			# Get POST Parameters
			temp_get = urllib.unquote_plus(semi[-1])
			self._AnalyzePostBody(temp_get)

			core.vars.config.PACKETS.append(self)

		else:
			# This is not a "GET" or "POST" request
			pass


	def _SearchBinaryData(self):
		"""
		Search for data within binary data.
		:return: Null
		"""
		a = binary_search(self.index, str(self.raw_packet))
		if a is not OKAY:
			self.binary_data.append([a['type'], a['name'], a['match']])

		if len(self.binary_data) is not 0:
			self.request_method = "BINARY"
			self.host = self.raw_packet[IP].src + "-->" + self.raw_packet[IP].dst
			core.vars.config.PACKETS.append(self)


	def _detect_param(self, field, val):
		isb64 = _is_base64(val)  	# Check if the data is base64 encoded
									# Check if the data is binary. If not, replace the regexes to run on the decoded data.

		# If the data is base64 get the value of the base64 decoded string
		if type(isb64) is str:
			val = isb64

		# If the field is JSON it will be parsed later on
		if "-JSON" in field:
			return

		# Do detection and pattern matching
		a = whoami(self.index, val, field)

		if a is not OKAY:
			if (a == "Longitude" or a == "Latitude") and self.l_or_l == False:
				self.l_or_l = True
			elif (a == "Longitude" or a == "Latitude") and self.l_or_l == True:
				a = "Latitude"
				self.loc = True
			elif a == "Coordinate":
				self.loc = True
			if isb64:
				self.marked_fields.append([field + " (b64)", a, val])
			else:
				self.marked_fields.append([field, a, val])


	def _CheckFields(self):
		"""
		Checks the information on the fields and try to match them to a known
		data type. If so, it will return it to another element of the object.
		:return: Nothing
		"""
		self.l_or_l = False
		self.loc = False
		if len(self.post_parameters) != 0:
			for fv in self.post_parameters:
				try:
					field = fv[0]
					val = fv[1]
				except:
					continue
				self._detect_param(field, val)

		if len(self.get_parameters) != 0:
			for fv in self.get_parameters:
				try:
					field = fv[0]
					val = fv[1]
				except:
					continue
				self._detect_param(field, val)

		if not self.loc:
			for fhv in self.marked_fields:
				if fhv[1] == "Longitude" or fhv[1] == "Latitude":
					self.marked_fields.remove(fhv)


if __name__ == "__main__":
	sys.stderr.write("This is a module...\n")
	sys.exit(ERR)
