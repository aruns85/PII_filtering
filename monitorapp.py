#!/usr/bin/env python3
import os
import sys
import time
import threading
import re

from zipfile import ZipFile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from apscheduler.schedulers.blocking import BlockingScheduler

#Default DIR Path
DIRECTORY_TO_WATCH = "/tmp/scan_dir"
DIRECTORY_TO_SCAN = "/tmp/todecode"#"/Users/saarun/sophos/todecode"
OUTFILES = "PII_filtered_"
REPLACE_TEXT = "file_path"

def performPII(filename):
    """
    Function to perform PII scan
    """
    print(f'***PERFORM PII: {filename}')
    with open(filename, "r") as f:
        fullfile = f.readlines()
    result = []
    for line in fullfile:
        if REPLACE_TEXT in line:
            res = re.sub(r"Users?\\+[a-zA-Z.0-9]+", r"Users\\<u>", line)
            res1 = re.sub(r':[\s]?"[a-zA-Z]:', r":<d>", res)
            result.append(res1)
    filteredFile = os.path.join(DIRECTORY_TO_SCAN, OUTFILES + filename.split("/")[-1])
    with open(filteredFile, "w") as fd:
        for line in result:
            fd.write(str(line))
    return

class Watcher:

    def __init__(self, watchdir):
        self.observer = Observer()
        self.watch_dir = watchdir

    def run(self):
        event_handler = Handler()
        if os.path.exists(self.watch_dir):
            self.observer.schedule(event_handler, self.watch_dir, recursive=True)
            self.observer.start()
            try:
                while True:
                    print(f'Watch Dir: {self.watch_dir} - Sleep 5')
                    time.sleep(5)
            except:
                self.observer.stop()
                print("Error")

            self.observer.join()
        else:
            print('Directory Doesnt Exist!!')
            return


class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):
        if event.is_directory:
            #print(f'No CHanges in the Directory-{event.src_path}')
            return None

        elif event.event_type == 'created' or \
            event.event_type == 'modified' and \
            OUTFILES not in event.src_path:
            # Take any action here when a file is first created.
            print(f"Received {event.event_type} event - {event.src_path}")
            if ".txt" in event.src_path and DIRECTORY_TO_SCAN not in event.src_path:
                #Find the TImestamp and EPOCH Time for Password
                print(f'File is : {event.src_path}')
                timestr = time.strftime("%Y_%m_%d_%I_%M_%S_%p")
                secret = int(time.mktime(time.strptime(timestr, "%Y_%m_%d_%I_%M_%S_%p")))
                dst = os.path.join(f"{DIRECTORY_TO_WATCH}", timestr+".zip")
                print(f'Encrypted File {timestr}.zip" with Password: {secret}')
                os.system(f'zip -j -P {secret} {dst} {event.src_path}')

                #Move the Zip file to a New directory
                if not os.path.exists(f'{DIRECTORY_TO_SCAN}'):
                    os.makedirs(f'{DIRECTORY_TO_SCAN}')
                os.system(f'mv {dst} {DIRECTORY_TO_SCAN}')
            elif ".txt" in event.src_path and DIRECTORY_TO_SCAN in event.src_path:
                #Original File after ZIP in the DESTINATION Directory for Scan
                print(f"Src File on Dest Dir: {event.src_path}")
                if os.path.exists(f'{event.src_path}'):
                    performPII(event.src_path)
                    os.system(f"rm {event.src_path}")
                else:
                    #Existing Original File Deleted
                    pass

            if ".zip" in event.src_path and DIRECTORY_TO_SCAN in event.src_path:
                print(f"File is : {event.src_path}")
                srcpath = event.src_path.split("/")
                filename = None
                for i in srcpath:
                    if ".zip" in i:
                        filename = i
                timestamp = filename.strip('.zip')
                secret = int(time.mktime(time.strptime(timestamp, "%Y_%m_%d_%I_%M_%S_%p")))
                sec = bytes(str(secret), 'utf-8')
                with ZipFile(event.src_path, 'r') as zipObj:
                    zipObj.extractall(DIRECTORY_TO_SCAN, pwd=sec)

if __name__ == '__main__':
    user_input = input("Enter the path of the Directory to Scan: ")

    if os.path.isdir(user_input):
        DIRECTORY_TO_WATCH = user_input
    else:
        assert os.path.exists(user_input), "I did not find the Directory to Scan"

    print(f"{DIRECTORY_TO_WATCH}")
    print(f"{DIRECTORY_TO_SCAN}")

    #Thread 1 to Watch the Directory for Txt File
    w = Watcher(DIRECTORY_TO_WATCH)
    out1 = threading.Thread(name='Scan New Txt File', target=w.run)
    out1.start()

    #Thread 2 to Scan the Directory for Zip File
    w1 = Watcher(DIRECTORY_TO_SCAN)
    out2 = threading.Thread(name='Scan Zip File', target=w1.run)
    out2.start()

    print("That's okay!! ALL Good")

'''
if __name__ == '__main__':
    scheduler = BlockingScheduler()
    w = Watcher()
    try:
        job = scheduler.add_job(w.run(), 'interval', seconds=10)
        scheduler.start()
    except Exception as e:
        print(f'Exception Recvd :{str(e)}')
        pass
'''
