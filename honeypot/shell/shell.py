import sys
import traceback

from grammar       import parse, TreeNode
from commands.base import Proc

def filter_ascii(string):
	string = ''.join(char for char in string if ord(char) < 128 and ord(char) > 32 or char in " ")
	return string

###

ELF_BIN_ARM  = "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00\xbc\x14\x01\x00\x34\x00\x00\x00\x54\x52\x00\x00\x02\x04\x00\x05\x34\x00\x20\x00\x09\x00\x28\x00\x1b\x00\x1a\x00"

globalfiles = {
    "/proc/mounts": """/dev/root /rom squashfs ro,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,noatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,noatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0
/dev/mtdblock10 /overlay jffs2 rw,noatime 0 0
overlayfs:/overlay / overlay rw,noatime,lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work 0 0
tmpfs /dev tmpfs rw,nosuid,relatime,size=512k,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,mode=600 0 0
debugfs /sys/kernel/debug debugfs rw,noatime 0 0\n""",
    "/proc/cpuinfo": """processor       : 0
model name      : ARMv6-compatible processor rev 7 (v6l)
BogoMIPS        : 697.95
Features        : half thumb fastmult vfp edsp java tls 
CPU implementer : 0x41
CPU architecture: 7
CPU variant     : 0x0
CPU part        : 0xb76
CPU revision    : 7

Hardware        : BCM2835
Revision        : 000e
Serial          : 0000000000000000\n""",
    "/proc/meminfo" :"""MemTotal:               1031016 kB
MemFree:                13548 kB
MemShared:              0 kB
Buffers:                98064 kB
Cached:                 692320 kB
SwapCached:             2244 kB
Active:                 563112 kB
Inact_dirty:            309584 kB
Inact_clean:            79508 kB
Inact_target:           190440 kB
HighTotal:              130992 kB
HighFree:               1876 kB
LowTotal:               900024 kB
LowFree:                11672 kB
SwapTotal:              1052248 kB
SwapFree:               1043908 kB
Committed_AS:           332340 kB\n """,
    "/etc/passwd" : """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
ntp:x:109:116::/home/ntp:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
nm-openvpn:x:118:126:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/bin/false
rtkit:x:119:127:RealtimeKit,,,:/proc:/bin/false
saned:x:120:128::/var/lib/saned:/bin/false
usbmux:x:121:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
mysql:x:123:133:MySQL Server,,,:/nonexistent:/bin/false\n""",
    "/etc/group" :"""root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:pulse
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-timesync:x:102:
systemd-network:x:103:
systemd-resolve:x:104:
systemd-bus-proxy:x:105:
input:x:106:
crontab:x:107:
syslog:x:108:
netdev:x:109:
messagebus:x:110:
uuidd:x:111:
ssl-cert:x:112:
lpadmin:x:113:
lightdm:x:114:
nopasswdlogin:x:115:
ntp:x:116:
mlocate:x:117:
ssh:x:118:
avahi-autoipd:x:119:
avahi:x:120:
bluetooth:x:121:
scanner:x:122:saned
colord:x:123:
pulse:x:124:
pulse-access:x:125:
nm-openvpn:x:126:
rtkit:x:127:
saned:x:128:
vboxsf:x:129:
vboxusers:x:131:
mysql:x:133:
wireshark:x:134: \n""",
    "/bin/echo": ELF_BIN_ARM,
    "/bin/busybox": ELF_BIN_ARM
}

def instantwrite(msg):
	sys.stdout.write(msg)
	sys.stdout.flush()

class Env:
	def __init__(self, output=instantwrite):
		self.files   = {}
		self.deleted = []
		self.events  = {}
		self.output  = output

	def write(self, string):
		self.output(string)

	def deleteFile(self, path):
		if path in self.files:
		    self.deleted.append((path, self.files[path]))
		    del self.files[path]

	def writeFile(self, path, string):
		if path in self.files:
		    self.files[path] += string
		else:
		    self.files[path] = string

	def readFile(self, path):
		if path in self.files:
		    return self.files[path]
		elif path in globalfiles:
		    return globalfiles[path]
		else:
		    return None

	def listen(self, event, handler):
		self.events[event] = handler

	def action(self, event, data):
		if event in self.events:
		    self.events[event](data)
		else:
		    print("WARNING: Event '" + event + "' not registered")

class RedirEnv:
	def __init__(self, baseenv, redir):
		self.baseenv = baseenv
		self.redir   = redir

	def write(self, string):
		self.baseenv.writeFile(self.redir, string)

	def deleteFile(self, path):
		self.baseenv.deleteFile(path)

	def writeFile(self, path, string):
		self.baseenv.writeFile(path, string)

	def readFile(self, path):
		self.baseenv.readFile(path)

	def listen(self, event, handler):
		self.baseenv.listen(event, handler)

	def action(self, event, data):
		self.baseenv.action(event, data)

class Command:
    def __init__(self, args):
        self.args          = args
        self.redirect_from   = None
        self.redirect_to     = None
        self.redirect_append = False
        self.shell           = Proc.get("sh")

    def run(self, env):
        if self.redirect_to != None:
            if not(self.redirect_append):
                env.deleteFile(self.redirect_to)
            env = RedirEnv(env, self.redirect_to)
        return self.shell.run(env, self.args)

    def __str__(self):
        return " ".join(self.args)

class CommandList:

    def __init__(self, mode, cmd1, cmd2):
        self.mode = mode
        self.cmd1 = cmd1
        self.cmd2 = cmd2

    def run(self, env):
        ret = self.cmd1.run(env)
        if (self.mode == "&&"):
            if (ret == 0):
                return self.cmd2.run(env)
            else:
                return ret
        if (self.mode == "||"):
            if (ret != 0):
                return self.cmd2.run(env)
            else:
                return ret
        if (self.mode == ";" or self.mode == "|"):
            return self.cmd2.run(env)

    def __str__(self):
        return "(" + str(self.cmd1) + self.mode + str(self.cmd2) + ")"

class Actions(object):
    def make_arg_noquot(self, input, start, end, elements):
	    return input[start:end]

    def make_arg_quot(self, input, start, end, elements):
        return elements[1].text

    def make_basecmd(self, input, start, end, elements):
        if isinstance(elements[1], TreeNode):
            l = []    
        else:
            l = [ elements[1] ]
        for e in elements[2].elements:
            if not(isinstance(e.elements[1], TreeNode)):
                l.append(e.elements[1])
                
        cmd = Command(l)
                
        # redirects
        for r in elements[4]:
            if r[0] == ">":
                cmd.redirect_to = r[1]
                cmd.redirect_append = False
            if r[0] == ">>":
                cmd.redirect_to = r[1]
                cmd.redirect_append = True
            if r[0] == "<":
                cmd.redirect_from = r[1]
        
        return cmd 

    def make_cmdop(self, input, start, end, elements):
        if isinstance(elements[2], TreeNode):
            return elements[0]
        else:
            return CommandList(elements[1].text, elements[0], elements[2])

    def make_cmdbrace(self, input, start, end, elements):
        return elements[3]

    def make_cmdlist(self, input, start, end, elements):
        if elements[1]:
            # Pipes not supported
            pass
        return elements[0]
        
    def make_redirect(self, input, start, end, elements):
        op  = elements[3].text
        arg = elements[7]
        return (op, arg)
        
    def make_redirects(self, input, start, end, elements):
        return elements

def run(string):
    return parse(filter_ascii(string).strip(), actions=Actions())

def test_shell():
    env = Env()
    while True:
        sys.stdout.write(" # ")
        sys.stdout.flush()
        line = sys.stdin.readline()
        sys.stdout.write(line)
        if line == "":
            break
        if line == "\n":
            continue
        line = line[:-1] 
        tree = run(line)
        tree.run(env)
        sys.stdout.flush()

