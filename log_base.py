import re
import threading
from time import sleep
import sys
import subprocess
from select import select
from io import TextIOWrapper, SEEK_SET
import json
from DelayedKeyboardInterrupt import DelayedKeyboardInterrupt

# Configuration
#################################################
REFRESH_AFTER = 2

services = []

ANALYSIS_TRIGGGER_FILE = 'TRIGGER_ANALYSIS'

LOGS_FOLDER = 'logs'

#################################################


lock = threading.Lock()
session_lock = threading.Lock()
current_session = 0
interrupt_received = threading.Event()
session_holder = {}
parent_service_log_holder = {}
parent_overview_holder = {}
is_analysis_on = False

def fetch_service_config():
    with open('./config.json') as config_file:
        json_data = config_file.read()
        converted_data = json.loads(json_data)
        return converted_data

def lock_and_update_dict(map, key, value):
    lock.acquire()
    map[key] = value
    if (lock.locked()):
        lock.release()

def close_session(ssh_uuid):
    try:
        session_lock.acquire(timeout=2)
        global current_session
        if (ssh_uuid in session_holder):
            session_holder[ssh_uuid].close()
            del session_holder[ssh_uuid]
            current_session -= 1
        if (session_lock.locked()):
            session_lock.release()
    except KeyboardInterrupt:
        if (session_lock.locked()):
            session_lock.release()
        raise

def checkIsError(line: str) -> bool:
    line = line.lower()
    errorTokens = ['error', 'exception']
    for errorToken in errorTokens:
        if (errorToken in line):
            return True
    return False

def run_local_command(command: str, buffer_size=1) -> tuple[str, str]:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=buffer_size,
        universal_newlines=True,
        text=True,
        shell=True
    )

    while process.poll() is None:
        out, _, _ = select([process.stdout, process.stderr], [], [])
        for line in out:
            line = line.readline().strip()
            if (line):
                if (checkIsError(line)):
                    yield (None, line)
                else:
                    yield (line, None)
    for line in process.stdout:
        line = line.strip()
        if (line):
            if (checkIsError(line)):
                yield (None, line)
            else:
                yield (line, None)

def get_log_files(service_name: str) -> tuple[TextIOWrapper, TextIOWrapper]:
    logTime = get_local_time('%d_%m_%Y')
    logFilename = '{}/{}_log_{}.log'.format(LOGS_FOLDER, service_name, logTime)
    errorFilename = '{}/{}_error_{}.log'.format(LOGS_FOLDER, service_name, logTime)
    logFile = open(logFilename, 'a+', buffering=1)
    errorFile = open(errorFilename, 'a+', buffering=1)
    return (logFile, errorFile)

def get_analysis_file(start_time: str) -> TextIOWrapper:
    analysis_filename = '{}/analysis_{}.log'.format(LOGS_FOLDER, start_time)
    analysis_file = open(analysis_filename, 'w')
    return analysis_file

def get_overview_file(start_time: str) -> TextIOWrapper:
    overview_filename = '{}/overview_{}.log'.format(LOGS_FOLDER, start_time)
    overview_file = open(overview_filename, 'w')
    return overview_file

def print_table(dictionary, outstream = sys.stdout):
    if (not dictionary.keys()):
        return
    max_key_length = max(len(key) for key in dictionary.keys())
    max_value_length = max(5, max(len(str(value)) for value in dictionary.values()))

    print('+' + '-' * (max_key_length + 2) + '+' + '-' * (max_value_length + 2) + '+', file=outstream)
    print('| {:<{}} | {:<{}} |'.format('Item', max_key_length, 'Count', max_value_length), file=outstream)
    print('+' + '-' * (max_key_length + 2) + '+' + '-' * (max_value_length + 2) + '+', file=outstream)

    for key, value in dictionary.items():
        print('| {:<{}} | {:<{}} |'.format(key, max_key_length, value, max_value_length), file=outstream)

    print('+' + '-' * (max_key_length + 2) + '+' + '-' * (max_value_length + 2) + '+', file=outstream)

def does_regex_match_analysis(lines, analysis, match_counts):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    for line in lines.split('\n'):
        line = ansi_escape.sub('', line)
        for tag, search_string in analysis.items():
            if(search_string in line):
                lock.acquire(timeout=2)
                if (tag not in match_counts):
                    match_counts[tag] = 1
                else:
                    match_counts[tag] += 1
                lock.release()

def check_for_date_change(
        service_name: str,
        outfile: TextIOWrapper,
        errfile: TextIOWrapper,
        old_day: str
    ) -> tuple[TextIOWrapper, TextIOWrapper, str]:
    new_day = get_local_time('%d')
    if (new_day == old_day):
        return (outfile, errfile, old_day)
    else:
        outfile.flush()
        errfile.flush()
        outfile.close()
        errfile.close()
        new_outfile, new_errfile = get_log_files(service_name)
        return (new_outfile, new_errfile, new_day)

def track_service(service_details, start_time):
    match_counts = dict()
    match_counts_overview = dict()
    global is_analysis_on
    current_day = get_local_time('%d')
    outfile, errfile = get_log_files(service_details['service_name'])
    while not interrupt_received.is_set():
        for line in run_local_command(f'docker logs --since={start_time} --follow {service_details["service_container"]}'):
            outfile, errfile, current_day = check_for_date_change(service_details['service_name'], outfile, errfile, current_day)
            if (line[0] != None):
                if (is_analysis_on):
                    if ('analysis' in service_details):
                        does_regex_match_analysis(line[0], service_details['analysis'], match_counts)
                    if ('overview' in service_details):
                        does_regex_match_analysis(line[0], service_details['overview'], match_counts_overview)
                outfile.write(line[0])
                outfile.write('\n')
                outfile.flush()
            else:
                if (is_analysis_on):
                    if ('analysis' in service_details):
                        does_regex_match_analysis(line[1], service_details['analysis'], match_counts)
                    if ('overview' in service_details):
                        does_regex_match_analysis(line[1], service_details['overview'], match_counts_overview)
                errfile.write(line[1])
                errfile.write('\n')
                errfile.flush()
            lock_and_update_dict(parent_service_log_holder, service_details["service_name"], match_counts)
            lock_and_update_dict(parent_overview_holder, service_details["service_name"], match_counts_overview)
            if (interrupt_received.is_set()):
                break
        start_time = "T".join(get_local_time('%Y-%m-%d %H:%M:%S').split())
        sleep(REFRESH_AFTER)
    print('Closing file: ', outfile, errfile)
    outfile.flush()
    errfile.flush()
    outfile.close()
    errfile.close()

def cleanup():
    if (session_lock.locked()):
        session_lock.release()
    if (lock.locked()):
        lock.release()
    for session in session_holder:
        session.close()

def get_server_time(ssh_client):
    stdin, stdout, stderr = ssh_client.exec_command("date +'%Y-%m-%d %H:%M:%S'")
    if (stderr.read().decode()):
        print("Error connecting to server.")
        return
    current_time = stdout.read().decode().rstrip()
    return current_time

def get_local_time(format: str) -> str:
    process = subprocess.Popen("date +'{}'".format(format), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(process.stdout)
    current_time:str = process.stdout.readline().decode().strip()
    return current_time

def start_tests():
    threads = []
    global is_analysis_on

    start_time = get_local_time('%Y-%m-%d %H:%M:%S')
    docker_format_start_time = "T".join(start_time.split())

    try:

        # Track Services
        for service in services:
            thread = threading.Thread(target=track_service, args=(service, docker_format_start_time))
            threads.append(thread)
            thread.start()

        while not interrupt_received.is_set():
            is_trigger_file_present = next(run_local_command('ls {} | grep {}'.format(LOGS_FOLDER, ANALYSIS_TRIGGGER_FILE)), None)
            with DelayedKeyboardInterrupt():
                if (is_analysis_on):
                    if (not is_trigger_file_present):
                        analysis_file.seek(0, SEEK_SET)
                        json.dump(parent_service_log_holder, analysis_file)
                        analysis_file.flush()
                        overview_file.seek(0, SEEK_SET)
                        json.dump(parent_overview_holder, overview_file)
                        overview_file.flush()
                        is_analysis_on = False
                        analysis_file.close()
                    else:
                        analysis_file.seek(0, SEEK_SET)
                        json.dump(parent_service_log_holder, analysis_file)
                        analysis_file.flush()
                        overview_file.seek(0, SEEK_SET)
                        json.dump(parent_overview_holder, overview_file)
                        overview_file.flush()
                else:
                    if (is_trigger_file_present):
                        is_analysis_on = True
                        current_time = get_local_time('%S_%M_%H_%d_%m_%Y')
                        analysis_file = get_analysis_file(current_time)
                        overview_file = get_overview_file(current_time)
                        json.dump(parent_overview_holder, overview_file)
                        json.dump(parent_service_log_holder, analysis_file)
                        analysis_file.flush()
                        overview_file.flush()

    except KeyboardInterrupt:
        interrupt_received.set()
        print('Keyboard Interrupt received, waiting for threads to exit.')

        for thread in threads:
            thread.join()

services = fetch_service_config()
start_tests()
