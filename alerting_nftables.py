import datetime
import logging
import os
import re

# Changing current working directory
try:
    os.chdir('C:\\Users\\Mike\\Documents\\CBE\\VII SEM\\Bezpieczny Dostęp do Internetu\\')

except NotADirectoryError:
    print('Error has occurred during changing the current working directory')
    exit(10000)

# ALERTS WILL BE SAVED IN A FILE AND ALSO SENT TO THE CONSOLE

# Creating logging object with name: nftables
logger = logging.getLogger('nftables')

# Definition of a destination: log file
alert_log = 'alerts_log.txt'
file_log_handler = logging.FileHandler(alert_log)
logger.addHandler(file_log_handler)

# Definition of a destination: console
stderr_log_handler = logging.StreamHandler()
logger.addHandler(stderr_log_handler)

# Definition of log format
log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_log_handler.setFormatter(log_format)
stderr_log_handler.setFormatter(log_format)

# Definition of a nftables log file
log_file_path = 'nft_log.txt'

# Definition of a regex patterns
network_attack_regex = re.compile(r''' 
PING\sFLOOD|
SYN\sFLOOD|
FIN\sSCAN|
XMAS\sSCAN|
Invalid\spackets|
NULL\sScan|
Possible\sDirbuster|
SSH\sBrute|
Connect\sScan|
SYN\sScan|
UDP\sScan
''', re.VERBOSE)
datetime_alerts_regex = re.compile(r'\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d,\d\d\d')    # 2020-11-16 17:24:12,540
datetime_log_regex = re.compile(r'\w\w\w\s\d\d\s\d\d:\d\d:\d\d')    # Nov 16 17:24:12

# Definition of network attacks
network_attacks = ['PING FLOOD', 'SYN FLOOD', 'FIN SCAN', 'XMAS SCAN', 'Invalid packets', 'NULL Scan',
                   'Possible Dirbuster', 'SSH Brute', 'Connect Scan', 'SYN Scan', 'UDP Scan']

# Acquiring today's date with time
time = datetime.datetime.now()

# THE SCRIPT WILL TRY TO READ THE DATE AND TIME FROM THE LAST LINE OF ALERT_LOG FILE.
# IT WILL USE THIS INFORMATION FOR READING THE NFTABLES LOG FILE - TO KNOW WHERE TO START LOOKING FOR ATTACK LOGS
try:
    with open(alert_log) as log_alerts:
        last_line = log_alerts.readlines()[-1]                                  # reading the last line
        mo = re.search(datetime_alerts_regex, last_line)                        # searching for date in that line
        time_string = re.sub(r',', r'.', mo.group())                            # changing 12,540 to 12.540
        time = datetime.datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S.%f')  # conversion from str to datetime object

except IndexError:
    print("There was an exception while reading alert.log file. The time is set to current time.")

# THE SCRIPT WILL EXTRACT THE DATE FROM EACH LOG, FORMAT IT AND THEN COMPARE IT WITH THE time VARIABLE
# IF IT FINDS THE LOGS THAT A DATE IS LATER THAN IT IS IN time VARIABLE, IT WILL SEARCH FOR ATTACK LOG
# IF THE ATTACK LOG IS FOUND, IT WILL RAISE A WARNING TO THE CONSOLE AND ALERT_LOG FILE
with open(log_file_path) as log_file:
    for log in log_file.readlines():
        mo = re.search(datetime_log_regex, log)                                             # searching for date in a log
        log_time = datetime.datetime.strptime(mo.group(), '%b %d %H:%M:%S').replace(2020)   # conversion from str to datetime object
        if log_time <= time:                                                                # dates comparison
            continue                                                                        # action for old logs
        else:
            mo = re.search(network_attack_regex, log)                                       # searching for attack info
            if mo.group() in network_attacks:                                               # checking if what was found is valid
                logger.warning(f'NETWORK ATTACK DETECTED: {mo.group()}')                    # raising a warning
