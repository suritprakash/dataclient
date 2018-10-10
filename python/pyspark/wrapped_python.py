#!/databricks/python/bin/python

#
# Copyright (C) 2017 Databricks, Inc.
#
# Portions of this software incorporate or are derived from software contained within Apache Spark,
# and this modified software differs from the Apache Spark software provided under the Apache
# License, Version 2.0, a copy of which you may obtain at
# http://www.apache.org/licenses/LICENSE-2.0
#

"""
# This script will run the provided executable in $2 as the user whose ID is $1. The new process
# will inherit the environment of the launching process.

# Usage: wrapped_python.py PYTHON_UID PYTHON_EXECUTABLE_PATH OTHER_PYTHON_ARGS
# Example: wrapped_python.py 1000 /databricks/python/bin/python -u /tmp/1504138606774/PythonShell.py
"""

import pwd
import os
import subprocess
import sys

SPARK_USER_GROUP = "spark-users"


# We throw an error if the group does not exist. We currently only call this on the spark-users
# group (above), which we create during container setup.
def get_gid_for_groupname(groupname):
    try:
        group_entry = subprocess.check_output(["getent", "group", groupname]).decode("utf-8")
    except subprocess.CalledProcessError as e:
        # returncode = 2 --> no such group
        if e.returncode == 2:
            raise RuntimeException("Attempted to get gid for nonexistent group: '%s'" % groupname)
        else:
            raise e
    return int(group_entry.split(":")[2].strip())


def get_or_create_uid_for_username(username):
    # We structure this as try-to-create, then get rather than try-to-get, create, then get in order
    # to avoid a race condition when multiple processes on the same node try to create
    try:
        subprocess.check_call([
            "sudo", "useradd",
            "--no-create-home",
            "--groups=%s" % SPARK_USER_GROUP,
            username,
        ])
    except subprocess.CalledProcessError as e:
        # returncode = 9 --> user already exists
        if e.returncode == 9:
            pass
        else:
            raise e

    uid_str = subprocess.check_output(["id", "-u", username]).decode("utf-8")
    return int(uid_str.strip())


def set_user_and_group_id(uid, gid):
    os.setgid(int(gid))

    # Setting the uid must be the last syscall we make, since once we change our uid we no
    # longer have permission to make syscalls
    os.setuid(int(uid))


def do_all_setup_for_username(username):
    # Only do this setup if we would actually change our user. This check allows us to run this code
    # as a non-root user.
    if username != pwd.getpwuid(os.getuid()).pw_name:
        # Must make sure that Spark user group exists before creating user
        spark_user_gid = get_gid_for_groupname(SPARK_USER_GROUP)
        uid = get_or_create_uid_for_username(username)
        if (os.environ.get("ENABLE_IPTABLES", "false") == "true" and
                "PYSPARK_GATEWAY_PORT" in os.environ):
            # Prepend a rule to the iptables chain in order to allow the user to connect
            # from the Python process back to the driver JVM. This code is only run on
            # the driver (PYSPARK_GATEWAY_PORT will not be defined on executors).
            gateway_port = int(os.environ["PYSPARK_GATEWAY_PORT"])
            subprocess.check_call([
                "iptables",
                "-I", "OUTPUT",
                "-m", "owner",
                "--uid-owner", str(uid),
                "-d", "127.0.0.1",
                "-p", "tcp",
                "--destination-port", str(gateway_port),
                "-j", "ACCEPT",
            ])
        set_user_and_group_id(uid, spark_user_gid)


if __name__ == "__main__":
    do_all_setup_for_username(sys.argv[1])
    program = sys.argv[2]
    args = sys.argv[2:]
    os.execvp(program, args)
