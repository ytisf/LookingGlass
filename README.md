# LookingGlass

## Abstract
LookingGlass is hosted at [Github](https://www.github.com) and is located at [https://LookingGlass.moriRT.com](https://lookingglass.morirt.com)

LookingGlass is a Python tool intended on assisting networking researchers in identifying specific patterns, regex and specific data in various encodings in the traffic. The intention of LookingGlass is to assist the researcher in identifying the data you're interested at rather then doing various searches and dedicated scripts.

LookingGlass is a parsing tool to assist you with your traffic research. It is designed to look (at the moment) only on HTTP requests (parameterized only!) and highlight specific information types. Currently, LookingGlass is hunting these particular data types:
  - IMEI
  - Credit Card numbers
  - Locations
  - IMSI
  - MSISDN
  - Longitudes & Latitudes
  - Emails
  - MAC addresses (within requests not in tuple)
  - IP Addresses (within requests not in tuple)

The data is searched within encodings such cas `base64`, `urlencoding`, `base58` and we try to eliminate false-positives with searching if data might be data like `unix epoch time`.

It will create two artifacts after execution:

  1. `filename.csv` - A CSV with all requests and parameters found, parsed.
  2. `filename.html` - An HTML report only with the possible hits of patterns described above.

A note for lazy - here is a 'help' with all arguments:
```
These are the possible arguments:
	-f, --file           Single file mode. Path to PCAP file.
	-d, --directory      Directory to scan PCAPs in.
	-l, --live           Run in live sniffing on adapter. For example 'eth0' or 'en0'. (not recommended)
	-v, --verbose        Show more information while running.
	-u, --user           User configurations to search.
	-k, --kml 			 If coordinates are found, save a KML file as well.
	-h, --help           Shows this help menu.
	--falpos             Ignore data types that are not reliable such as MSISDN.

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
```

*Little Comment* - Because we get to record directly on devices sometimes, and on Android the recorder does not add the IP layer, we have added support for that as well.

## Installation
It's acutally kinda straightforward. Just go into this folder with a terminal (assuming Linux/OSX) and with pip run:
```bash
pip install -r requirements.txt
```

## Execution Types
### Single
Running the script on 1 PCAP file. Example of usage will be:
```bash
looking_glass.py -f 'FILENAME.pcap'
```

### Folder Run
Running the script against several PCAPs within a single directory. Please notice that due to the laziness of the authors we are only searching for files with a .pcap extension.

Usage example:
```bash
looking_glass.py -d 'DIRECTORY'
```

### Customized Search
Create a file of your choosing and add the terms you want to search. For string search just add:
```
normal, SM-J700, Device Model
```
The `'normal'` means text search, the `'SM-J700'` is the string to search and the `'Device Model'` is the title for that search. Please notice that LookingGlass will attempt to search for the data in binary form as well as in different encodings such as Base64 and so on.

Another type of search is a regex search. For example:
```
regex, (com\.([a-zA-z]+\.){1,3}[a-zA-z]+), Android Package Name
```

There is also binary data search:
```
binary, 0363646e0377, Binary User Name
```

And Hash searches:
```
md5sum, abc, MD5 of Name
sha1sum, text_here, SHA1 of name
sha256, text_here, SHA256 of name
sha512, text_here, SHA512 of name
```

Also, field names:
```
in_field_name, lat, Might be Latitude
field_name_is, MSISDN, Phone number
```

`in_field_name` will yield a result of the string is within an HTTP parameter whil `field_name_is` will yeild a response only if the field name is exactly a string match.

After you have saved the file you can call it like this:
```bash
python looking_glass.py -f pcap_file.pcap -u user_search.txt
```


## License - GPLv3
[Yuval tisf Nativ](https://www.github.com/yitsf), [Dagan Pasternak](https://www.github.com/daganp)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

## Flow Chart
FlowChart created using the awesome [Mermaid](https://github.com/knsv/mermaid) project.

Source can be found at `mermaid.md` and you can use [this](http://knsv.github.io/mermaid/live_editor/#/view/Z3JhcGggVEQKICAgIHN0YXJ0W0xvb2tpbmdHbGFzcyBTdGFydF0KICAgIHN0YXRle0xpdmUvUENBUH0KICAgIHVzZXJfcGFyYW1bTG9hZCBVc2VyIFBhcmFtZXRlcnNdCiAgICBzdGFydC0tPiB1c2VyX3BhcmFtCiAgICB1c2VyX3BhcmFtIC0tPnN0YXRlCiAgICBhZGFwdFtTdGFydCBTbmlmZmluZ10KICAgIHN0YXRlLS0-IHxMaXZlfCBhZGFwdAogICAgY29sZFtSZWFkIFBDQVAgRmlsZV0KICAgIHN0YXRlLS0-IHxQQ0FQfCBjb2xkCiAgICB0aHJlYWRpbmdbQ3JlYXRlIFRocmVhZCBmb3IgRWFjaCBQYWNrZXRdCiAgICBjb2xkLS0-dGhyZWFkaW5nCiAgICBhZGFwdC0tPnRocmVhZGluZwogICAgaWRlbnR7SXMgSFRUUFJlcXVlc3Q_fQogICAgdGhyZWFkaW5nLS0-aWRlbnQKICAgIHBhcmFtc1tHZXRQYXJhbWV0ZXJzXQogICAgYmluW0RvUmF3U2VhcmNoXQogICAgaWRlbnQtLT58SFRUUFJlcXVlc3R8cGFyYW1zCiAgICBpZGVudC0tPnxCaW5hcnl8YmluCiAgICB2YXJzW0VuY29kaW5ncyBTZWFyY2hdCiAgICBkZWNvZGVbRGVjb2RlUGFyYW1zXQogICAgcGFyYW1zLS0-ZGVjb2RlCiAgICBiaW4tLT52YXJzCiAgICBkZWNvZGUtLT52YXJzCiAgICBqb2luW0pvaW5UaHJlYWRzXQogICAgdmFycy0tPmpvaW4KICAgIGNzdltXcml0ZUNTVl0KICAgIGh0bWxbV3JpdGVIVE1MXQogICAgam9pbi0tPmNzdgogICAgbWF0Y2h7TWF0Y2hlcyA_fQogICAgY3N2LS0-bWF0Y2gKICAgIG1hdGNoLS0-fFllc3xodG1sCiAgICBtYXRjaC0tPnxOb3xRdWl0CiAgICBodG1sLS0-UXVpdA) link to edit it.

![LookingGlass FlowChart](https://raw.githubusercontent.com/ytisf/LookingGlass/master/FlowChart.png)

## Future Developments

### Version 1.0 - Venus
- [x] Base.

### Version 1.1 - Bromhilda
- [x] **BugFix** - Fix CSS writer, which is an idiotic idea anyway.
- [x] **BugFix** - If encountering Longitude for the 2nd time have it change to Latitude.
- [x] **BugFix** - Make argument parsing done in a manner that is not embarassing to a 3 years old.
- [x] **Feature** - Add email regex.
- [x] **Feature** - Enable a flag to disable 'problematic' false-positive matches such as MSISDN.
- [x] **Improvments** - Set `host` and `URI` in the report to a code tag.
- [x] **Improvments** - Build a requirment file.
- [x] **Improvments** - Change verbosity option when exeuting on multiple files.

### Version 1.2 - Lia
- [x] **Feature** - Handeling JSON Requests
- [x] **Feature** - Handeling XML Requests

### Version 1.3 - Gaia
- [x] **BugFix** - Fixing various bugs.
- [x] **BugFix** - Patching reports.

### Version 1.4 - Benzaiten
- [x] **Feature** - Binary search.
- [x] **Feature** - Add support for user based binary search.
- [x] **Feature** - Ability to sniff live traffic.
- [x] **Improvments** - Normal log file.
- [x] **Improvments** - Preparation for different protocols.

### Version 1.5 - Fariero
- [x] **Feature** - Export coordinations as KML.
- [x] **Improvments** - Add IP address regex.
- [x] **Improvments** - Several bug fixes and stability.

### Version 1.5.1 - Fariero
- [x] **BugFix** - Bugfix in binary search.
- [x] **BugFix** - Bugfix in hash search and display.

### Version 1.6 - GEN
- [x] **Feature** - Search for field names (for example, passwords)
- [x] **Feature** - Handeling Responses


### In the Distant Future - The year 2000
- [ ] Real cookies support
- [ ] Reconstruction
