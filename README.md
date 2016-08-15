# LookingGlass

## Abstract
LookingGlass is a parsing tool to assist you with your traffic research. It is designed to look (at the moment) only on HTTP requests (parameterized only!) and highlight specific information types. Currently, LookingGlass is hunting these particular data types:
  - IMEI
  - Credit Card numbers
  - Locations
  - IMSI
  - MSISDN
  - Longitudes & Latitudes
  - Emails

The data is searched within encodings such as `base64`, `urlencoding`, `base58` and we try to eliminate false-positives with searching if data might be data like `unix epoch time`.

It will create two artifacts after execution:

  1. `filename.csv` - A CSV with all requests and parameters found, parsed.
  2. `filename.html` - An HTML report only with the possible hits of patterns described above.

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
- [x] **Improvments** - Set `host` and `URI` in the report to a code tag.
- [x] **Feature** - Add email regex.
- [x] **BugFix** - Make argument parsing done in a manner that is not embarassing to a 3 years old.
- [x] **Improvments** - Change verbosity option when exeuting on multiple files.
- [x] **Feature** - Enable a flag to disable 'problematic' false-positive matches such as MSISDN.
- [x] **Improvments** - Build a requirment file.

### In the Distant Future - The year 2000
- [ ] Real cookies support
- [ ] Reconstruction
- [ ] Handeling responses
- [ ] Handeling JSON Requests
- [ ] Handeling XML Requests
- [ ] Have some sort of API to add search options
