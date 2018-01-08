#!/usr/bin/python

# General imports
try:
	import os
	import sys
	import time
	import glob
	import config
	import getopt
	import hashlib
	import logging
	import datetime
	import simplekml
	import unicodedata
except ImportError, e:
	sys.stderr.write("\033[91m[!]\033[0m\tError with importing.\n")
	sys.stderr.write("\033[91m[!]\033[0m\tPlease try running 'sudo pip install -r requirements.txt'.\n")
	sys.stderr.write("\033[91m[!]\033[0m\tAnd if you still have an issue open a ticket.\n")
	sys.stderr.write(str(e))
	sys.exit()

# Grouppings imports
from threading import Thread
from multiprocessing import Process, Queue

# App imports
import core.vars
from core.packets_do import *


try:
	# Silently Import Scapy:
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # shut scapy up
	from scapy.all import *
except ImportError, e:
	sys.stderr.write("\033[91m[!]\033[0m\tUnable to import Scapy.\n")
	sys.exit(ERR)

### HERE ENDS IMPORTS SECTIONS


def _is_root():
	"""
	Checks if the user running the script it root or not.
	:return: Boolean
	"""
	if os.geteuid() != 0:
		return False
	else:
		return True


def _export_to_kml(fname):
	"""
	This function iterates over everything that might be coordinates and save it
	as a KML file for later usage.
	:param fname: String of file name to save at.
	:return: Boolean
	"""

	global verbosity

	temp_coords = {"Longitude": None, "Latitude": None}

	kml = simplekml.Kml()

	for pckt in core.vars.config.PACKETS:
		try:
			for field, possible_match, value in pckt.marked_fields:

				if possible_match == "Coordinate":
					lat, lon = value.split(",")
					kml.newpoint(name=("Packet#%s:Field-'%s'" % (pckt.index, field)), coords=[(lat,lon)])

				elif possible_match == "Longitude" or possible_match == "Latitude":
					if field.lower() == ("longitude", "long", "lon", "lo"):
						temp_coords['Longitude'] = value
					elif field.lower() == ("latitude", "lati", "lat", "la"):
						temp_coords['Latitude'] = value
					else:
						if temp_coords['Latitude'] is None:
							temp_coords['Latitude'] = value
						elif temp_coords['Longitude'] is None:
							temp_coords['Longitude']= value
						else:
							pass

					if temp_coords['Latitude'] is not None and temp_coords['Longitude'] is not None:
						kml.newpoint(name=("Packet#%s:Field-'%s'" % (pckt.index, field)), coords=[(temp_coords['Longitude'], temp_coords['Latitude'])])
						temp_coords = {"Longitude": None, "Latitude": None}

		except:
			continue

	try:
		kml.save(core.vars.REPORT_FOLER + fname + ".kml")
		if verbosity:
			sys.stdout.write("\033[92m[+]\033[0m\tFile '%s.kml' has been saved.\n" % fname)
	except:
		sys.stderr.write("\033[91m[!]\033[0m\tSomething went wrong with writing KML for '%s'.\n" % fname)
		return ERR

	return OKAY


def md5(fname):
	"""
	Gets a file path and returns the MD5 hex digest.
	:param fname: filepath
	:return: hexdigest or ERR
	"""
	hash_md5 = hashlib.md5()
	try:
		with open(fname, "rb") as f:
			for chunk in iter(lambda: f.read(4096), b""):
				hash_md5.update(chunk)
	except IOError, e:
		sys.stderr.write("\033[91m[!]\033[0m\tCould not open file '%s'.\n%s\n" % (fname, e))
		return ERR
	return hash_md5.hexdigest()


def load_pcap(path_to_pcap):
	"""
	Try loading a PCAP file and return packets handler.
	:param path_to_pcap: path to pcap file
	:return: handler or ERR
	"""
	try:
		a = PcapReader(path_to_pcap)
		file_size = os.path.getsize(path_to_pcap)
		b = file_size/1024/1024
		sys.stdout.write("\033[92m[+]\033[0m\tFile '%s' should take around %s minutes to analyze.\n" % (path_to_pcap, b))
		return a
	except IOError, e:
		sys.stderr.write("\033[91m[!]\033[0m\tCould not read PCAP '%s'.\n" % path_to_pcap)
		return ERR
	except scapy.error.Scapy_Exception, e:
		sys.stderr.write("\033[91m[!]\033[0m\tCould not read PCAP '%s'.\nScapy raised error %s.\n" % (path_to_pcap, e))
		return ERR


def _do_packet(pckt, i):
	"""
	Creates an object to handle each packet. Called as threat. Has timelock
	to prevent too many jobs on the same time. Ugly work around but saves us
	some trouble on some machines
	:param pckt: scapy packet object
	:param i: counter in pcap file
	:return: nothing
	"""
	thisPackt = HandlePacket(i, pckt)
	time.sleep(DELAY_BETWEEN_THREADS)


def _save(file_name):
	"""
	Creates the CSV file with all packets parsed.
	:return: Nothing
	"""
	report_file_name = file_name.split("/")[-1]
	report_file_name = report_file_name[:-5]
	f = open(REPORT_FOLER+report_file_name+".csv", WRITE_BINARY)
	for packt in core.vars.config.PACKETS:
		if packt.binary_flag is False:
			line = str(packt.index) + SEPARATOR + packt.request_method + SEPARATOR
			line += packt.host + SEPARATOR + packt.path + SEPARATOR
			if packt.request_method == "GET":
				line += str(packt.get_parameters) + "\n"
			elif packt.request_method == "POST":
				line += str(packt.get_parameters) + SEPARATOR + str(packt.post_parameters) + "\n"
			f.write(line)
	f.close()
	return OKAY


def _to_presentable(string):
	"""
	Convert as string to presentable and drop the rest.
	:param string: string to convert
	:return: ascii string.
	"""
	ret_me = ""
	for chr in string:
		try:
			b = chr.encode('ascii', 'replace')
			ret_me += b
		except:
			ret_me += "!"
	return ret_me


def _build_html(file_name):
	"""
	Ugly HTML report generator
	Yacky!

	Please don't read this function.
	:return: Vomit
	"""
	markdown_text = ""
	poss_packets = []
	gets = 0
	posts = 0
	binary_counter = 0
	counter = 0
	for pckt in core.vars.config.PACKETS:
		if (len(pckt.marked_fields) > 0) or (len(pckt.binary_data) > 0):
			poss_packets.append(counter)
		if pckt.request_method is "GET":
			gets += 1
		if pckt.request_method is "POST":
			posts += 1
		if pckt.request_method is "BINARY":
			binary_counter += 1
		counter += 1

	markdown_text += "<html>"
	markdown_text += "<head><link rel=\"stylesheet\" href=\"markdown.css\"><style>body {box-sizing: border-box;min-width: 200px;max-width: 980px;margin: 0 auto;padding: 45px;}</style></head>"
	markdown_text += "<body><article class=\"markdown-body\">"
	markdown_text += "<h1>Report - <code>%s</code></h1>" % file_name

	# General summary
	markdown_text += "<h2>Summary</h2>"
	if file_flag:
		markdown_text += "<p>PCAP size: <code>%s</code></p>\n" % os.path.getsize(file_name)
		markdown_text += "<p>PCAP MD5: <code>%s</code></p>\n" % md5(file_name)
	elif folder_flag:
		markdown_text += "<p>PCAP size: <code>%s</code></p>\n" % os.path.getsize(file_name)
		markdown_text += "<p>PCAP MD5: <code>%s</code></p>\n" % md5(file_name)
	markdown_text += "<p>Date of Analysis: <code>%s</code></p>\n" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	markdown_text += "<p>Total of GETs: <code>%s</code></p>\n" % gets
	markdown_text += "<p>Total of POSTs: <code>%s</code></p>\n" % posts

	# Hits summary
	markdown_text += "<h2>Hits Summary</h2>"
	markdown_text += "<ul>"
	for pos_ind in poss_packets:
		this_index = core.vars.config.PACKETS[pos_ind].index
		for field, pos, val in core.vars.config.PACKETS[pos_ind].marked_fields:
			markdown_text += "<li><a href=\"#packet%s\">Packet %s</a>:   <code>%s</code> - <code>%s</code> might be %s</li>" % (this_index, this_index, field, val, pos)
		for name, pos, val in core.vars.config.PACKETS[pos_ind].binary_data:
			if type(val) is int:
				markdown_text += "<li><a href=\"#packet%s\">Packet %s[BIN]</a>:   Found possible hit on <code>%s</code> at offset %s</li>" % (this_index, this_index, pos, val)
			else:
				markdown_text += "<li><a href=\"#packet%s\">Packet %s[BIN]</a>:   <code>%s</code> %s - might be %s</li>" % (this_index, this_index, val, name, pos)
	markdown_text += "</ul>"

	# All possible hits - full report
	markdown_text += "<h2>Possible Hits (%s)</h2>" % len(poss_packets)
	for pos_ind in poss_packets:

		# If binary
		if core.vars.config.PACKETS[pos_ind].binary_flag == True:
			markdown_text += "<a name=\"packet%s\"><h3>Packet #%s</h3></a>" % (core.vars.config.PACKETS[pos_ind].index, core.vars.config.PACKETS[pos_ind].index)
			markdown_text += "<p>Host: <code>%s</code>.</p>" % core.vars.config.PACKETS[pos_ind].host
			markdown_text += "<p>Request Type: <code>%s</code>.</p>" % core.vars.config.PACKETS[pos_ind].request_method

			markdown_text += "<h4>Possible Hits</h4>"
			for name, pos, val in core.vars.config.PACKETS[pos_ind].binary_data:
				markdown_text += "<p><code>%s:%s</code> at offset %s.</p>" % (_to_presentable(str(val)), _to_presentable(name) ,_to_presentable(str(pos)))
			markdown_text += "<hr>"

		# If HTTP Request
		else:
			markdown_text += "<a name=\"packet%s\"><h3>Packet #%s</h3></a>" % (core.vars.config.PACKETS[pos_ind].index, core.vars.config.PACKETS[pos_ind].index)
			markdown_text += "<p>Host: <code>%s</code>.</p>" % core.vars.config.PACKETS[pos_ind].host
			markdown_text += "<p>URL: <code>%s</code>.</p>" % core.vars.config.PACKETS[pos_ind].path
			markdown_text += "<p>Request Type: <code>%s</code>.</p>" % core.vars.config.PACKETS[pos_ind].request_method

			if len(core.vars.config.PACKETS[pos_ind].get_parameters) != 0:
				markdown_text += "<h4>Get Parameters</h4>"
				markdown_text += "<table><tr><th>Field</th><th>Value</th></tr>"
				for fv in core.vars.config.PACKETS[pos_ind].get_parameters:
					try:
						field = fv[0]
						val = fv[1]
					except IndexError:
						continue
					try:
						markdown_text += "<tr><td>%s</td><td align='left'>%s</td></tr>" % (_to_presentable(field), _to_presentable(val))
					except:
						markdown_text += "<tr><td>%s</td><td align='left'>%s</td></tr>" % ("BINARY", "BINARY")
				markdown_text += "</table>"

			if len(core.vars.config.PACKETS[pos_ind].post_parameters) != 0:
				markdown_text += "<h4>Post Parameters</h4>"
				markdown_text += "<table><tr><th>Field</th><th>Value</th></tr>"
				for fv in core.vars.config.PACKETS[pos_ind].post_parameters:
					try:
						field = fv[0]
						val = fv[1]
					except IndexError:
						continue
					try:
						markdown_text += "<tr><td>%s</td><td align='left'>%s</td></tr>" % (_to_presentable(field), _to_presentable(val))
					except:
						markdown_text += "<tr><td>%s</td><td align='left'>%s</td></tr>" % ("BINARY", "BINARY")
				markdown_text += "</table>"

			markdown_text += "<h4>Possible Hits</h4>"
			for field, pos, val in core.vars.config.PACKETS[pos_ind].marked_fields:
				markdown_text += "<p><code>%s</code> (%s) might be %s.</p>" % (_to_presentable(field),_to_presentable(val),_to_presentable(pos))
			markdown_text += "<hr>"

	markdown_text += "</article>"
	markdown_text += "</body>"
	markdown_text += "</html>"

	report_file_name = file_name.split("/")[-1]
	report_file_name = report_file_name[:-5]

	f = open(REPORT_FOLER+report_file_name+".html", WRITE_BINARY)
	f.write(markdown_text)
	f.close()
	return OKAY


def _print_help():
	"""
	If you're reading this, please go to: https://www.codecademy.com/learn/python
	:return:
	"""

	banner = """\033[94m
  _                _    _              ____ _
 | |    ___   ___ | | _(_)_ __   __ _ / ___| | __ _ ___ ___
 | |   / _ \ / _ \| |/ / | '_ \ / _` | |  _| |/ _` / __/ __|
 | |__| (_) | (_) |   <| | | | | (_| | |_| | | (_| \__ \__ \\
 |_____\___/ \___/|_|\_\_|_| |_|\__, |\____|_|\__,_|___/___/
                                |___/                       \033[0m"""
	help_menu = """
	%s
	\033[91mVersion %s - %s.
	Written by %s and %s.\033[0m

	This program will try to iterate over a PCAP file and get
	interesting information out of it. It is currently looking for
	the following types of information:
				- [ ] IMEI
				- [ ] Credit Card numbers
				- [ ] Locations
				- [ ] IMSI
				- [ ] MSISDN
				- [ ] Longitudes & Latitudes
				- [ ] Email addresses

	Please run the script this way:
		\033[36m%s -f file.pcap
		%s -d directory\033[0m

	These are the possible arguments:
		\033[36m-f, --file           Single file mode. Path to PCAP file.
		-d, --directory      Directory to scan PCAPs in.
		-l, --live           Run in live sniffing on adapter. For example 'eth0' or 'en0'. (not recommended)
		-v, --verbose        Show more information while running.
		-u, --user           User configurations to search.
		-k, --kml 			 If coordinates are found, save a KML file as well.
		-h, --help           Shows this help menu.
		--falpos             Ignore data types that are not reliable such as MSISDN.\033[0m

	The options for user defined serrch are:
		'regex' - A regex to search. For example 'regex, (com\.([a-zA-z]+\.){1,3}[a-zA-z]+), Android Package Name'.
		'noraml' - Regular search for data. For example 'normal, SM-J700, Device Model'.
		'binary' - Hex encoded binary data. For example 'binary, 0363646e0377, BinarySearch'.
		'md5sum' - MD5 value of data. For example 'md5sum, 5554353444, MD5 of MSISDN'.
		'sha1sum' - SHA1 value of data. For example 'sha1sum, text_here, SHA1 of name'.
		'sha256' - SHA256 value of data. For example 'sha256, text_here, SHA256 of name'.
		'sha512' - SHA512 value of data. For example 'sha512, text_here, SHA512 of name'.
		'in_field_name' - Value to be in an HTTP parameter name. For example 'in_field_name, lat, Might be Latitude'.
		'field_name_is' - Exact value of HTTP parameter name. For example 'field_name_is, MSISDN, Phone number'.

	In the folder \033[36m'Report'\033[0m you will have a CSV file and an HTML file for each
	of the PCAPs you executed the program on. The HTML report contains just the results which
	matches one of the data-types. In the CSV report you shall have all the requests divided
	by param-value keys in case you would like to go through them manually or give them to
	another application to analyze.
	""" % (banner, NUMERIC_VERSION, NAME_VERSION, AUTHORS[0], AUTHORS[1], sys.argv[0].split("/")[-1], sys.argv[0].split("/")[-1])
	print help_menu
	sys.exit(2)


def _print_banner():
	banner = """\033[94m
      _                _    _              ____ _
     | |    ___   ___ | | _(_)_ __   __ _ / ___| | __ _ ___ ___
     | |   / _ \ / _ \| |/ / | '_ \ / _` | |  _| |/ _` / __/ __|
     | |__| (_) | (_) |   <| | | | | (_| | |_| | | (_| \__ \__ \\
     |_____\___/ \___/|_|\_\_|_| |_|\__, |\____|_|\__,_|___/___/
                                    |___/                       \033[0m
    	\033[91mVersion %s - %s.
    	Written by %s and %s.\033[0m
    """ %(NUMERIC_VERSION, NAME_VERSION, AUTHORS[0], AUTHORS[1])
	print banner


def _execution_wrapper(file_name):

	global verbosity
	global false_positives
	global kml_flag

	pckts = load_pcap(file_name)  # Read packets from PCAP
	if pckts == ERR:
		return ERR

	jobs = []

	i = 0
	for pckt in pckts:
		i += 1
		# Non threading for test:
		# _do_packet(pckt, i)

		# Threading
		th = Thread(target=_do_packet, args=(pckt, i))
		th.daemon = True
		th.start()
		jobs.append(th)

		if i % PROGRESS_PRINT == 0:
			gets = 0
			posts = 0
			for pckt in core.vars.config.PACKETS:
				if pckt.request_method == "GET":
					gets += 1
				elif pckt.request_method == "POST":
					posts += 1
			if verbosity:
				sys.stdout.write("\033[92m[+]\033[0m\tDone with %s packets.\n" % i)

	for j in jobs:
		j.join()

	if verbosity:
		sys.stdout.write("\033[92m[+]\033[0m\tAll threads done.\n")
	_save(file_name)
	if verbosity:
		sys.stdout.write("\033[92m[+]\033[0m\tCreated a full CSV report.\n")
	_build_html(file_name)
	if verbosity:
		sys.stdout.write("\033[92m[+]\033[0m\tCreated a full HTML report.\n")
	if kml_flag:
		_export_to_kml(file_name.split("/")[-1])
	core.vars.config.PACKETS = []
	sys.stdout.write("\033[92m[+]\033[0m\tFinished with '%s'.\n" % file_name)


def _live_execution_wrapper(adapter):

	global verbosity
	global false_positives
	jobs = []
	i = 0

	def _create_thread_for_packet(pckt):
		global i
		print i
		th = Thread(target=_do_packet, args=(pckt, i))
		th.daemon = True
		th.start()
		jobs.append(th)
		i += 1

	if not _is_root():
		sys.stderr.write("\033[91m[!]\033[0m\tTo run in live mode you must be root.\n")
		sys.stderr.write("\033[91m[!]\033[0m\tPlease run again with sudo.\n")
		sys.exit(ERR)

	try:
		sys.stdout.write("\033[92m[+]\033[0m\tNow sniffing on '%s'.\n" % adapter)
		sniff(iface=adapter, prn=_create_thread_for_packet, filter="ip")
	except:
		sys.stderr.write("\033[91m[!]\033[0m\tCould not sniff traffic on adapter '%s'.\n" % adapter)
		return ERR

	sys.stdout.write("\n\033[92m[+]\033[0m\tGot quit. Generating report.\n")
	for j in jobs:
		j.join()
	_save("LiveCapture.pcap")
	_build_html("LiveCapture.pcap")
	sys.stdout.write("\033[92m[+]\033[0m\tFinished with LiveCapture.\n")
	return OKAY


def _read_user_search_file(path_to_conf):

	global verbosity

	rules = []

	try:
		f = open(path_to_conf, READ)
		raw_conf = f.readlines()
		f.close()
	except IOError, e:
		sys.stdout.write("\033[91m[!]\033[0m\tCould read configuration file '%s'.\nError:%s.\n" % (path_to_conf, e))
		sys.exit(ERR)

	i = 0

	if len(raw_conf) == 0:
		sys.stderr.write("\033[91m[-]\033[0m\tThere are no lines on the user-configuartion file.\n")
		sys.exit(ERR)

	else:

		for line in raw_conf:
			try:
				t, search_term, name = line.split(", ")
			except:
				sys.stderr.write("\033[91m[-]\033[0m\tError parsing line %s in the configuration file. Skipping.\n" % i)
				continue

			if t == "normal":
				rules.append([t, search_term, name])

			elif t == "regex":
				try:
					reg = re.compile(search_term)
					rules.append([t, reg, name])
				except:
					sys.stderr.write("\033[91m[-]\033[0m\tThe term '%s' is not a valid regex.\n" % search_term)
					continue

			elif t == "binary":
				try:
					rules.append([t, bytes(bytearray.fromhex(search_term)), name])
				except ValueError:
					sys.stderr.write("\033[91m[-]\033[0m\tError while converting binary search in name '%s'. Probably odd chars.\n" % name.strip())
					continue

			elif t == "md5sum":
				rules.append([t, hashlib.md5(search_term).hexdigest(), name])

			elif t == "sha1sum":
				rules.append([t, hashlib.sha1(search_term).hexdigest(), name])

			elif t == "sha256":
				rules.append([t, hashlib.sha256(search_term).hexdigest(), name])

			elif t == "sha512":
				rules.append([t, hashlib.sha512(search_term).hexdigest(), name])

			elif t == "field_name_is":
				rules.append([t, search_term, name])

			elif t == "in_field_name":
				rules.append([t, search_term, name])

			else:
				sys.stdout.write("\033[91m[-]\033[0m\tFirst delimiter must be \n\t\t\t'regex', 'normal', 'md5sum', 'sha1sum', 'sha256', 'in_field_name', 'field_name_is' or 'sha512'.\n\t\t\t '%s' is unknown.\n" % t)
				continue

			i += 1

	if verbosity:
		sys.stdout.write("\033[92m[+]\033[0m\tParsed %s user-based rules.\n" % len(rules))

	return rules


def _create_css():
	"""
	This functino creates the CSS file for the report.
	:return: Nothing
	"""
	f = open(core.vars.REPORT_FOLER + "/" + "markdown.css", WRITE_BINARY)
	f.write(core.vars.HARCODED_FUCKING_CSS)
	f.close()


def main():

	# Set 'em global
	global file_flag
	global folder_flag
	global kml_flag
	global verbosity
	global false_positives

	# Initial values
	file_flag = False
	folder_flag = False
	help_flag = False
	kml_flag = False
	verbosity = False
	live_capture = False
	user_requests = False
	location = ""
	rules_location = ""
	false_positives = False			# These are fields like MSISDN which might
									# yield too many flase-positives. If this is
									# on, ignore those fields.

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hf:d:l:u:k:v", ["file=", "directory=", "user=", "live=", "verbose", "kml", "falpos"])
	except getopt.GetoptError:
		_print_help()

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			_print_help()
		elif opt in ("-f", "--file"):
			file_flag = True
			location = arg
		elif opt in ("-d", "--directory"):
			folder_flag = True
			location = arg
		elif opt in ("-v", "--verbose"):
			verbosity = True
			VERBOSITY = True
		elif opt in ("-l", "--live"):
			live_capture = True
			adapter = arg
		elif opt in ("-k", "--kml"):
			kml_flag = True
		elif opt in ("-u", "--user"):
			user_requests = True
			rules_location = arg
		elif opt == "--falpos":
			false_positives = True
			FALSE_POSITIVES = True

	# Checks if got one or the other
	if file_flag is False and folder_flag is False and live_capture is False:
		_print_help()

	# Print banner & execution mode
	_print_banner()

	if verbosity:
		sys.stdout.write("\033[92m[+]\033[0m\tRunning in verbose mode.\n")

	if false_positives:
		sys.stdout.write("\033[92m[+]\033[0m\tDisabling false-positive prone searches.\n")

	if user_requests:
		core.vars.config.USER_REQUESTS = _read_user_search_file(rules_location)
		sys.stdout.write("\033[92m[+]\033[0m\tUsing %s rules from file '%s'.\n" % (len(core.vars.config.USER_REQUESTS), rules_location))

	# If everything went okay the program will not attempt to start
	if file_flag:
		sys.stdout.write("\033[92m[+]\033[0m\tRunning in single file mode.\n")
		_execution_wrapper(location)
		_create_css()
		sys.stdout.write("\n")

	elif folder_flag:
		try:
			str_read = "%s/*.pcap" % location
			files = glob(str_read)
		except:
			sys.stdout.write("\033[91m[!]\033[0m\tCould not list files in directory '%s'.\n" % location)
			sys.exit()

		# Check if there are files in the folder.
		if len(files) == 0:
			_print_help()
			sys.stderr.write("\033[91m[!]\033[0m\tCould find and files in the directory '%s'.\n" % location)
			sys.exit()

		sys.stdout.write("\033[92m[+]\033[0m\tRunning on directory '%s'.\n" % location)
		_create_css()
		for file in files:
			sys.stdout.write("\033[92m[+]\033[0m\tExecuting file '%s'.\n" % file)
			_execution_wrapper(file)
		sys.stdout.write("\n")

	elif live_capture:
		_live_execution_wrapper(adapter)
		_create_css()

	else:
		_print_help()


if __name__ == "__main__":
	main()
