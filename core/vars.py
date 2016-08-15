
import config
from core.css import css

# GLOBALS
OKAY                    = 0
ERR                     = -1
DELAY_BETWEEN_THREADS   = 0.002
PROGRESS_PRINT          = 100
WRITE_BINARY            = 'wb'
REPORT_FOLER            = "Report/"
OUTPUT_FILE             = REPORT_FOLER + "Report.csv"
SEPARATOR               = " ; "
TEMP_MARKDOWN_LOC       = 'temp.md'
HTML_REPORT             = REPORT_FOLER + "Report.html"
HARCODED_FUCKING_CSS    = css
READ                    = 'r'
READ_BINARY             = 'rb'
WRITE_BINARY            = 'wb'
WRITE                   = 'w'

# SHARED
config.PACKETS          = []
FALSE_POSITIVES         = False
VERBOSITY               = False
config.USER_REQUESTS    = []

# VERSION INFORMATION
NAME                    = "LookingGlass"
NUMERIC_VERSION         = 1.1
NAME_VERSION            = "Bromhilda"
AUTHORS                 = ["Yuval tisf Nativ", "Dagan Pasternak"]
THIS_YEAR               = 2016

# REGEXES:
SINGLE_COORD            = r'^(([\+\-])?\d{1,3}\.\d{2,17})$'
COORDINATES             = r'^(([\+\-])?\d{1,3}\.\d{2,17}).+(([\+\-])?\d{1,3}\.\d{2,17})$'
EMAIL                   = r'([a-zA-Z0-9\-\.\_]+(\@| at )[a-zA-Z0-9\-\.\_]{3,16}(\.|dot| dot )[a-zA-Z0-9\-\.\_]{2,3})'
