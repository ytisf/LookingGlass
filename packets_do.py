import time
import config
import base64
import urllib
import binascii
from vars import *
from scapy.all import *
from tester import *
import vars

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
	s = ''.join([s.strip() for s in s.split("\n")])
	try:
		enc = base64.b64encode(base64.b64decode(s)).strip()
		return enc == s
	except TypeError:
		return False
	except UnicodeEncodeError:
		return False


class HandlePacket():
	"""
	General packet handler.
	Currently only works on HTTP Requests.
	"""
	def __init__(self, index, packet):
		self.index = index
		self.raw_packet = packet
		self.request_method = None
		self.time = None
		self.host = None
		self.path = None
		self.content_type = None
		self.payload = None
		self.get_parameters = []
		self.post_parameters = []
		self.marked_fields = []

		self._isHTTPRequest()
		if self.request_method == "GET" or self.request_method == "POST":
			self._CheckFields()

	def _isHTTPRequest(self):
		"""
		If the packet is an HTTPRequest, try to extract the fields in them.
		:return:
		"""

		if self.raw_packet.haslayer(http.HTTPRequest):

			if self.raw_packet[http.HTTPRequest].getfieldval('Method') == "GET":

				if "?" in self.raw_packet[http.HTTPRequest].getfieldval('Path'):
					# Parameterized GET
					self.request_method = "GET"
					self.host = self.raw_packet[http.HTTPRequest].getfieldval('Host')
					self.path = self.raw_packet[http.HTTPRequest].getfieldval('Path')
					self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.raw_packet.time))

					temp_get = urllib.unquote_plus(self.raw_packet[http.HTTPRequest].getfieldval('Path'))
					if temp_get.find("?") == -1:
						return
					params = temp_get[temp_get.find("?") + 1:]
					params = params.split("&")
					ret_gets = []
					for i in params:
						self.get_parameters.append(i.split("="))

					vars.config.PACKETS.append(self)

				else:
					# Non parameterized GET
					pass

			elif self.raw_packet[http.HTTPRequest].getfieldval('Method') == "POST":
				self.request_method = "POST"
				self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.raw_packet.time))
				self.host = self.raw_packet[http.HTTPRequest].getfieldval('Host')
				self.path = self.raw_packet[http.HTTPRequest].getfieldval('Path')

				self.content_type = self.raw_packet[http.HTTPRequest].getfieldval('Content-Type')
				self.payload = self.raw_packet[http.HTTPRequest].payload

				temp_get = str(self.raw_packet[http.HTTPRequest].getfieldval('Path'))
				temp_get = urllib.unquote_plus(temp_get)
				params = temp_get[temp_get.find("?") + 1:]
				params = params.split("&")
				for i in params:
					self.get_parameters.append(i.split("="))

				temp_get = str(self.raw_packet[http.HTTPRequest].payload)
				temp_get = urllib.unquote_plus(temp_get)
				params = temp_get[temp_get.find("?") + 1:]
				params = params.split("&")
				for i in params:
					self.post_parameters.append(i.split("="))

				vars.config.PACKETS.append(self)

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
			if temp_get.find("?") == -1:
				return
			params = temp_get[temp_get.find("?") + 1:]
			params = params.split("&")
			ret_gets = []
			for i in params:
				self.get_parameters.append(i.split("="))
			vars.config.PACKETS.append(self)

		elif "POST " in str(self.raw_packet.original) and "Host: " in str(self.raw_packet.original) and "HTTP/1. " in str(self.raw_packet.original):

			self.request_method = "POST"
			semi = self.raw_packet.original[self.raw_packet.original.find("POST "):].split("\r\n")
			self.time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.raw_packet.time))
			for item in semi:
				if ("GET " or "POST ") in item:
					self.request_method = item[:item.find(" ")]
					self.path = urllib.unquote_plus(
						item[item.find(self.request_method) + len(self.request_method):item.find(" HTTP/1.")])
				else:
					try:
						key, value = item.split(": ")
						if key == "Host":
							self.host = value
					except:
						pass

			temp_get = urllib.unquote_plus(self.path)
			if temp_get.find("?") == -1:
				return
			params = temp_get[temp_get.find("?") + 1:]
			params = params.split("&")
			ret_gets = []
			for i in params:
				self.get_parameters.append(i.split("="))

			# Handle POST parameters
			post_line = urllib.unquote_plus(semi[-1])
			if temp_get.find("?") == -1:
				return
			params = temp_get[temp_get.find("?") + 1:]
			params = params.split("&")
			ret_gets = []
			for i in params:
				self.post_parameters.append(i.split("="))

			vars.config.PACKETS.append(self)

		else:
			# No TCP?
			pass

	def _CheckFields(self):
		"""
		Checks the information on the fields and try to match them to a known
		data type. If so, it will return it to another element of the object.
		:return: Nothing
		"""
		l_or_l = False
		loc = False
		if len(self.post_parameters) != 0:
			for fv in self.post_parameters:
				try:
					field = fv[0]
					val = fv[1]
				except:
					continue

				isb64 = _is_base64(val)  # Check if the data is base64 encoded

				# Check if the data is binary. If not, replace the regexes to run on the decoded data.
				if type(isb64) is str:
					val = isb64

				a = whoami(val)
				if a is not OKAY:
					if isb64:
						self.marked_fields.append([field + " (b64)", a, val])
					else:
						self.marked_fields.append([field, a, val])
					if (a == "Longitude" or a == "Latitude") and l_or_l == False:
						l_or_l = True
					elif (a == "Longitude" or a == "Latitude") and l_or_l == True:
						loc = True
					elif a == "Coordinate":
						loc = True

		if len(self.get_parameters) != 0:
			for fv in self.get_parameters:
				try:
					field = fv[0]
					val = fv[1]
				except:
					continue

				isb64 = _is_base64(val)  # Check if the data is base64 encoded

				# Check if the data is binary. If not, replace the regexes to run on the decoded data.
				if type(isb64) is str:
					val = isb64

				a = whoami(val)
				if a is not OKAY:
					if isb64:
						self.marked_fields.append([field + " (b64)", a, val])
					else:
						self.marked_fields.append([field, a, val])
					if (a == "Longitude" or a == "Latitude") and l_or_l == False:
						l_or_l = True
					elif (a == "Longitude" or a == "Latitude") and l_or_l == True:
						loc = True
					elif a == "Coordinate":
						loc = True

		if not loc:
			for fhv in self.marked_fields:
				if fhv[1] == "Longitude" or fhv[1] == "Latitude":
					self.marked_fields.remove(fhv)
