#!/usr/bin/python
import sys
import subprocess
import os
import logging

_, launcher, cwd, port_num, debug_id, debug_options, debuggee = sys.argv

vspd = os.path.join(os.path.dirname(launcher), 'visualstudio_py_debugger.py')

command = ['lldb-6.0', '-b',
            '-O', 'command script import "%s"' % vspd,
            '-O', 'script import os; visualstudio_py_debugger.debug("import adapter; adapter.main.run_tcp_session(4711, {\\\"logLevel\\\":%d})", %s, "%s", "%s", os.getpid(), "code")' %
                (logging.DEBUG, port_num, debug_id, debug_options)]

print command

subprocess.call(command, cwd=cwd)
