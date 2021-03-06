import os
import time
from watchdog.events import PatternMatchingEventHandler
from watchdog.observers import Observer

import MSP
from db import CommitRequest

LOG_DIR = "/var/log/"
LOG_PATTERN = "*/modsec_audit.log"
LOG_FILE = "/var/log/modsec_audit.log"

class ModsecEventHandler(PatternMatchingEventHandler):
    patterns = [LOG_PATTERN]

    def on_modified(self, event):
        try:
            content = ""
            with open(LOG_FILE, "r+") as fd:
                if os.fstat(fd.fileno()).st_size == 0:
                    return
                content = fd.read()
                fd.truncate(0)

            print("Detected new change...")

            audit = MSP.Audit(content)

            for req in audit.reqs:
                print("Committing new request...")
                CommitRequest(req)
            print("Requests committed!")
        except:
            # Make sure we crash all the way if something goes wrong in this thread
            os._exit(1)


if __name__ == "__main__":
    print("Starting observer...")

    event_handler = ModsecEventHandler()
    observer = Observer()
    observer.schedule(event_handler, LOG_DIR, recursive=False)
    observer.start()

    print("Observer started!")

    try:
        while 1:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down observer...")
        observer.stop()
    observer.join()
    print("Observer shut down!")
