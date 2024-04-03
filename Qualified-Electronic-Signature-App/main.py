import os
import re
import sys
from subprocess import Popen, PIPE
from time import sleep


def check_external_drive(callback):
    DISKUTIL = ['/usr/sbin/diskutil', 'activity']

    while True:
        with Popen(DISKUTIL, stdout=PIPE, encoding='UTF-8') as diskutil:
            # Detect the first subsequent "Disk Appeared" event
            for line in diskutil.stdout:
                if line.startswith('***DiskAppeared'):
                    match = re.search(r"DAVolumeName = '([^']+)'", line)

                    if match:
                        volume_name = match.group(1)
                        external_drive_path = f'/Volumes/{volume_name}/'
                        sleep(5)
                        callback(external_drive_path)

                    break
                sleep(5)


def main():
    def on_external_drive_change(external_drive_path):
        print("Detected change in external drive:", external_drive_path)

        if os.path.exists(external_drive_path):
            files = os.listdir(external_drive_path)
            print("Files on the external drive:")
            for file in files:
                print(file)
        # Do something with the external drive path

    try:
        check_external_drive(on_external_drive_change)
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
