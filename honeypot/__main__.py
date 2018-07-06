import signal

from telnet import Telnetd
from util.dbg import dbg

def signal_handler(signal, frame):
	dbg('Ctrl+C')
	srv.stop()

signal.signal(signal.SIGINT, signal_handler)

srv = Telnetd(2223)
srv.run()