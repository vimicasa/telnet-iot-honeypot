import struct
import socket
import traceback
import time
import string

from session import Session
from welcome import Welcome
from util.dbg import dbg
from util.config import config

TELNET_ISSUE = "\nTELNET session now in ESTABLISHED state\n"

class Telnetd:
	cmds   = {}
	cmds[240] = "SE   - subnegoation end"
	cmds[241] = "NOP  - no operation"
	cmds[242] = "DM   - data mark"
	cmds[243] = "BRK  - break"
	cmds[244] = "IP   - interrupt process"
	cmds[245] = "AO   - abort output"
	cmds[246] = "AYT  - are you there"
	cmds[247] = "EC   - erase char"
	cmds[248] = "EL   - erase line"
	cmds[249] = "GA   - go ahead"
	cmds[250] = "SB   - subnegotiation"
	cmds[251] = "WILL - positive return"
	cmds[252] = "WONT - negative return"
	cmds[253] = "DO   - set option"
	cmds[254] = "DONT - unset option"
	cmds[255] = "IAC  - interpret as command"

	SE   = 240
	NOP  = 241
	DM   = 242
	BRK  = 243
	IP   = 244
	AO   = 245
	AYT  = 246
	EC   = 247
	EL   = 248
	GA   = 249
	SB   = 250
	WILL = 251
	WONT = 252
	DO   = 253
	DONT = 254
	IAC  = 255

	# Options
	NAWS = 31

	def __init__(self, port):
		self.host    = "0.0.0.0"
		self.port    = port
		self.sock    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.do_run  = True

	def run(self):
		self.sock.bind((self.host, self.port))
		self.sock.listen(10)
		dbg("Socket open on port " + str(self.port))
		while self.do_run:
			try:
				self.handle()
			except:
				traceback.print_exc()
			# ONLY HANDLE ONE CLIENT
			# self.stop()
		self.sock.close()
		dbg("Socket Closed")

	def handle(self):
		conn = False
		try:
			conn, addr = self.sock.accept()
			dbg("Client connected at " + str(addr))

			sess = TelnetSess(self, conn, addr)
			sess.loop()
		except:
			traceback.print_exc()

		if conn:
			conn.close()

	def stop(self):
		self.do_run = False

class TelnetSess:
	def __init__(self, serv, sock, remote):
		self.serv    = serv
		self.sock    = sock
		self.timeout = config.get("timeout", optional=True, default=15.0) # Read timeout
		self.maxtime = config.get("maxtime", optional=True, default=50.0) # Max session time
		self.db_id   = 0
		self.remote  = remote
		self.session = None	

	def loop(self):
		self.session = Session(self.send_string, self.remote[0])

		dbg("Setting timeout to " + str(self.timeout) + " seconds")
		self.sock.settimeout(self.timeout)

		try:

			# Kill of Session if longer than self.maxtime
			ts_start = int(time.time())

			#Welcome Protocol
			Welcome(self).generateWelcome()
			
			self.send_string(TELNET_ISSUE)
			self.send_string("\r\nWelcome to EmbyLinux 3.13.0-24-generic\r\n")
			self.send_string(Session.prompt)
			
			while True:
				l = self.recv_line()
				
				try:
					self.session.shell(l)
				except:
					traceback.print_exc()
					self.send_string("sh: error\r\n")

				if ts_start + self.maxtime < int(time.time()):
					dbg("Session too long. Killing off.")
					break

		except socket.timeout:
			dbg("Connection timed out")
		except EOFError:
			dbg("Connection closed")

		Session.end(self.session)

	def test_naws(self):
		#dbg("TEST NAWS")
		if self.test_opt(Telnetd.NAWS):
			self.need(Telnetd.IAC)
			self.need(Telnetd.SB)
			self.need(Telnetd.NAWS)

			w = self.recv_short()
			h = self.recv_short()

			self.need(Telnetd.IAC)
			self.need(Telnetd.SE)

			#dbg("TEST NAWS OK " + str(w) + "x" + str(h))
		elif byte == Telnetd.WONT:
			pass
			#dgb("TEST NAWS FAILED")
		else:
			raise ValueError()

	def test_linemode(self):
		#dbg("TEST LINEMODE")
		if self.test_opt(34):
			self.need(Telnetd.IAC)
			self.need(Telnetd.SE)
	
	

	def test_opt(self, opt, future=True):

		self.send(Telnetd.IAC)
		if future:
			self.send(Telnetd.WILL)
		else:
			self.send(Telnetd.DO)
		self.send(opt)

	def send(self, byte):
		self.sock.send(chr(byte))

	def send_string(self, msg):
		self.sock.send(msg)

	def recv(self):
		byte = self.sock.recv(1)
		if len(byte) == 0:
			raise EOFError
		byte = ord(byte)
		return byte

	def recv_line(self):
		line = ""
		while True:
			byte = self.recv()
			if byte == Telnetd.IAC:
				byte = self.recv()
				self.process_cmd(byte)
			elif byte == ord("\r"):
				pass
			elif byte == ord("\n"):
				break
			else:
				line = line + chr(byte)
		#dbg("RECV STRING " + line)
		return line

	def recv_short(self):
		bytes = self.sock.recv(2)
		short = struct.unpack("!H", bytes)[0]
		#dbg("RECV SHORT " + str(short))
		return short

	def need(self, byte_need):
		byte = ord(self.sock.recv(1))
		if byte != byte_need:
			dbg("BAD  " + "PROTOCOL ERROR. EXIT.")
			raise ValueError()
		return byte

	def process_cmd(self, cmd):
		if cmd == Telnetd.DO:
			byte = self.recv()
			self.send(Telnetd.IAC)
			self.send(Telnetd.WONT)
			self.send(byte)
		if cmd == Telnetd.WILL or cmd == Telnetd.WONT:
			byte = self.recv()
