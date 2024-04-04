import re
from subprocess import Popen, PIPE


def check_external_drive():
    DISKUTIL = ["/usr/sbin/diskutil", "activity"]

    with Popen(DISKUTIL, stdout=PIPE, encoding="UTF-8") as diskutil:
        for line in diskutil.stdout:
            if line.startswith("***DiskAppeared"):
                match = re.search(r"DAVolumeName = '([^']+)'", line)
                if match:
                    volume_name = match.group(1)
                    print(volume_name)
                    if "<null>" in volume_name:
                        print("not found")
                        return None
                    external_drive_path = f"/Volumes/{volume_name}/"
                    return external_drive_path
    return None
