
import datetime, re

# Constraints:  Year must be 4 digits
#               American month-first date format is NOT allowed
# Examples:     23/2/2022  02_02_2016  '15 October 2021' 2024-05-26  2012/jan/13  etc.

MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")

def ParseBasicDate(txt):
    m = re.match(r"^(\d{1,4})[\.\- /](\w{1,9})[\.\- /](\d{1,4})$", txt)
    if not m:
        raise ValueError('Date format is invalid. (Ok formats: 23.2.2022 2022-04-04 "15 oct 2022")')

    # --- Month ---
    smon = m.group(2)
    if smon.isalpha():
        try:
            mon = MONTHS.index(smon[:3].lower()) + 1
        except ValueError:
            raise ValueError("Invalid month name '%s'" % (smon[:3],))  # from None  # backcompat put this back in when we drop py2
    else:
        mon = int(smon)
    if mon < 1 or mon > 12:
        raise ValueError("month %d not in range 1-12" % (mon,))

    # --- Day and Year ---
    g1 = m.group(1)
    g3 = m.group(3)
    # We already know they're digits thanks to the regex.
    # Now one value must be length 4 and the other must then be length 1 or 2.
    if len(g3) == 4 and len(g1) in (1, 2):
        day = int(g1)
        year = int(g3)
    elif len(g1) == 4 and len(g3) in (1, 2):
        day = int(g3)
        year = int(g1)
    else:
        raise ValueError("Year must be 4 digits and day must be 1 or 2 digits")

    return datetime.date(day=day, month=mon, year=year)

