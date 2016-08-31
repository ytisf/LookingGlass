# LookingGlass

## Abstract
LookingGlass is hosted at [Github](https://www.github.com) and is located at [https://LookingGlass.moriRT.com](https://lookingglass.morirt.com)

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
-f, --file           Single file mode. Path to PCAP file.
-d, --directory      Directory to scan PCAPs in.
-l, --live           Run on a live adapter and sniff. (not recommended)
-v, --verbose        Show more information while running.
-u, --user           User configurations to search.
-k, --kml            If coordinates are found, save a KML file as well.
-h, --help           Shows this help menu.
--falpos             Ignore data types that are not reliable such as MSISDN.
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
md5hash, abc, MD5 of Name
sha1hash, text_here, SHA1 of name
sha256, text_here, SHA256 of name
sha512, text_here, SHA512 of name
```


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

## Version 1.6 - No-Name-Yet
- [ ] **Feature** - Search for field names (for example, passwords)
- [ ] **Feature** - Handeling Responses

### In the Distant Future - The year 2000
- [ ] Real cookies support
- [ ] Reconstruction
