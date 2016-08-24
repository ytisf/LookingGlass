#!/usr/bin/python

# General imports
import os
import sys
import time
import glob
import config
import getopt
import hashlib
import logging
import datetime
import unicodedata

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
		line = str(packt.index) + SEPARATOR + packt.request_method + SEPARATOR
		line += packt.host + SEPARATOR + packt.path + SEPARATOR
		if packt.request_method == "GET":
			line += str(packt.get_parameters) + "\n"
		elif packt.request_method == "POST":
			line += str(packt.get_parameters) + SEPARATOR + str(packt.post_parameters) + "\n"
		f.write(line)
	f.close()


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
	counter = 0
	for pckt in core.vars.config.PACKETS:
		if len(pckt.marked_fields) > 0:
			poss_packets.append(counter)
		if pckt.request_method is "GET":
			gets += 1
		if pckt.request_method is "POST":
			posts += 1
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
	markdown_text += "</ul>"

	# All possible hits - full report
	markdown_text += "<h2>Possible Hits (%s)</h2>" % len(poss_packets)
	for pos_ind in poss_packets:
		markdown_text += "<a name=\"packet%s\"><h3>Packet #%s</h3></a>" % (core.vars.config.PACKETS[pos_ind].index, core.vars.config.PACKETS[pos_ind].index)
		markdown_text += "<p>Host: <code>%s</code>.</p>" % core.vars.config.PACKETS[pos_ind].host
		markdown_text += "<p>URL: <code>%s</code>.</p>" % core.vars.config.PACKETS[pos_ind].path
		markdown_text += "<p>Request Type: <code>%s</code>.</p>" % core.vars.config.PACKETS[pos_ind].request_method

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
		-v, --verbose        Show more information while running.
		-u, --user           User configurations to search.
		-h, --help           Shows this help menu.
		--falpos             Ignore data types that are not reliable such as MSISDN.\033[0m

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
	core.vars.config.PACKETS = []
	sys.stdout.write("\033[92m[+]\033[0m\tFinished with '%s'.\n" % file_name)


def _read_user_search_file(path_to_conf):

	global verbosity

	rules = []

	try:
		f = open(path_to_conf, READ)
		raw_conf = f.read()
		f.close()
	except IOError, e:
		sys.stdout.write("\033[91m[!]\033[0m\tCould read configuration file '%s'.\nError:%s.\n" % (path_to_conf, e))
		sys.exit(ERR)

	i = 0
	for line in raw_conf.split("\n"):
		if len(line) == 0:
			continue
		try:
			t, search_term, name = line.split(", ")
		except:
			sys.stdout.write("\033[91m[-]\033[0m\tError parsing line %s in the configuration file. Skipping.\n" % i)
			i += 1
			continue

		if t == "normal":
			rules.append([t, search_term, name])
		elif t == "regex":
			try:
				reg = re.compile(search_term)
				rules.append([t, reg, name])
			except:
				sys.stdout.write("\033[91m[-]\033[0m\tThe term '%s' is not a valid regex.\n" % search_term)
				i += 1
				continue
		else:
			sys.stdout.write("\033[91m[-]\033[0m\tFirst delimiter must be 'regex' or 'normal', not '%s'.\n" % t)
			i += 1
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
	global verbosity
	global false_positives

	# Initial values
	file_flag = False
	folder_flag = False
	help_flag = False
	verbosity = False
	user_requests = False
	location = ""
	rules_location = ""
	false_positives = False			# These are fields like MSISDN which might
									# yield too many flase-positives. If this is
									# on, ignore those fields.

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hf:d:u:v", ["file=", "directory=", "user=", "verbose", "falpos"])
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
		elif opt in ("-u", "--user"):
			core.vars.config.USER_REQUESTS = _read_user_search_file(arg)
			user_requests = True
			rules_location = arg
		elif opt == "--falpos":
			false_positives = True
			FALSE_POSITIVES = True

	# Checks if got one or the other
	if file_flag is False and folder_flag is False:
		_print_help()


	# Print banner & execution mode
	_print_banner()

	if verbosity:
		sys.stdout.write("\033[92m[+]\033[0m\tRunning in verbose mode.\n")

	if false_positives:
		sys.stdout.write("\033[92m[+]\033[0m\tDisabling false-positive prone searches.\n")

	if user_requests:
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

	else:
		_print_help()


if __name__ == "__main__":
	main()
