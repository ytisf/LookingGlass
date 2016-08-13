#!/usr/bin/python

import os
import sys
import time
import config
import datetime
import unicodedata
import codecs
import logging
import hashlib
import glob


from multiprocessing import Process, Queue, Pool
from threading import Thread

import vars
from packets_do import *


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
		logging.info("PCAP '%s' has been read." % path_to_pcap)
		file_size = os.path.getsize(path_to_pcap)
		b = file_size/1024/1024
		sys.stdout.write("\033[92m[+]\033[0m\tFile '%s' should take around %s minutes to analyze.\n" % (path_to_pcap, b))
		return a
	except IOError, e:
		sys.stderr.write("\033[91m[!]\033[0m\tCould not read PCAP '%s'.\n" % path_to_pcap)
		sys.exit(ERR)


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
	for packt in vars.config.PACKETS:
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
	for pckt in vars.config.PACKETS:
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
	markdown_text += "<h1>Report - <code>%s.pcap</code></h1>" % file_name
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
	markdown_text += "<h2>Possible Hits (%s)</h2>" % len(poss_packets)
	for pos_ind in poss_packets:
		markdown_text += "<h3>Packet #%s</h3>" % vars.config.PACKETS[pos_ind].index
		markdown_text += "<p>Host: <code>%s</code>.</p>" % vars.config.PACKETS[pos_ind].host
		markdown_text += "<p>URL: <code>%s</code>.</p>" % vars.config.PACKETS[pos_ind].path
		markdown_text += "<p>Request Type: <code>%s</code>.</p>" % vars.config.PACKETS[pos_ind].request_method

		markdown_text += "<h4>Get Parameters</h4>"
		markdown_text += "<table><tr><th>Field</th><th>Value</th></tr>"
		for fv in vars.config.PACKETS[pos_ind].get_parameters:
			try:
				field = fv[0]
				val = fv[1]
			except IndexError:
				continue
			try:
				markdown_text += "<tr><td>%s</td><td align='right'>%s</td></tr>" % (_to_presentable(field), _to_presentable(val))
			except:
				markdown_text += "<tr><td>%s</td><td align='right'>%s</td></tr>" % ("BINARY", "BINARY")
		markdown_text += "</table>"

		markdown_text += "<h4>Post Parameters</h4>"
		markdown_text += "<table><tr><th>Field</th><th>Value</th></tr>"
		for fv in vars.config.PACKETS[pos_ind].post_parameters:
			try:
				field = fv[0]
				val = fv[1]
			except IndexError:
				continue
			try:
				markdown_text += "<tr><td>%s</td><td align='right'>%s</td></tr>" % (_to_presentable(field), _to_presentable(val))
			except:
				markdown_text += "<tr><td>%s</td><td align='right'>%s</td></tr>" % ("BINARY", "BINARY")
		markdown_text += "</table>"

		markdown_text += "<h3>Possible Hits</h3>"
		for field, pos, val in vars.config.PACKETS[pos_ind].marked_fields:
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

	Please run the script this way:
		\033[36m%s -f file.pcap
		%s -d directory\033[0m

	It will (OVER)write the report at the \033[36m'Report'\033[0m folder.
	\033[36m'Report.csv'\033[0m is a CSV with all fields and \033[36m'Report.html'\033[0m is the
	formalized HTML report with the interesting fields.
	""" % (banner, NUMERIC_VERSION, NAME_VERSION, AUTHORS[0], AUTHORS[1], sys.argv[0].split("/")[-1], sys.argv[0].split("/")[-1])
	print help_menu
	sys.exit()


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

	pckts = load_pcap(file_name)  # Read packets from PCAP

	jobs = []

	i = 0
	for pckt in pckts:
		i += 1
		th = Thread(target=_do_packet, args=(pckt, i))
		th.daemon = True
		th.start()
		jobs.append(th)

		if i % PROGRESS_PRINT == 0:
			gets = 0
			posts = 0
			for pckt in vars.config.PACKETS:
				if pckt.request_method == "GET":
					gets += 1
				elif pckt.request_method == "POST":
					posts += 1
			sys.stdout.write("\033[92m[+]\033[0m\tDone with %s packets.\n" % i)

	for j in jobs:
		j.join()

	sys.stdout.write("\033[92m[+]\033[0m\tAll threads done.\n")
	_save(file_name)
	sys.stdout.write("\033[92m[+]\033[0m\tCreated a full CSV report.\n")
	_build_html(file_name)
	sys.stdout.write("\033[92m[+]\033[0m\tCreated a full HTML report.\n")
	vars.config.PACKETS = []

def _create_css():
	f = open(vars.REPORT_FOLER + "/" + "markdown.css", WRITE_BINARY)
	f.write(vars.HARCODED_FUCKING_CSS)
	f.close()


def main():
	global file_flag
	global folder_flag
	file_flag = False
	folder_flag = False

	# Shitty way to do argument parsing but couldn't give a fuck
	if len(sys.argv) != 3:
		_print_help()

	if sys.argv[1] == "-f":
		file_flag = True

	elif sys.argv[1] == "-d":
		folder_flag = True

	_print_banner()
	if file_flag:
		sys.stdout.write("\033[92m[+]\033[0m\tRunning in single file mode.\n")
		_execution_wrapper(sys.argv[2])
		_create_css()

	elif folder_flag:
		try:
			str_read = "%s/*.pcap" % sys.argv[2]
			files = glob(str_read)
		except:
			sys.stdout.write("\033[91m[!]\033[0m\tCould not list files in directory '%s'.\n" % sys.argv[2])
			sys.exit()

		# Check if there are files in the folder.
		if len(files) == 0:
			_print_help()
			sys.exit()

		sys.stdout.write("\033[92m[+]\033[0m\tRunning on directory '%s'.\n" % sys.argv[2])
		_create_css()
		for file in files:
			sys.stdout.write("\033[92m[+]\033[0m\tExecuting file '%s'.\n" % file)
			_execution_wrapper(file)

	else:
		_print_help()


if __name__ == "__main__":
	main()
