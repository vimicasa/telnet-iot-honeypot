import string

from util.config import config

class Welcome: 
    def __init__(self, telSess):
		self.telSess = telSess        

    def defaultWelcome(self):
        self.telSess.test_opt(1)
        self.telSess.test_opt(3)
        self.telSess.test_opt(24,False)
        self.telSess.test_opt(31,False)
        self.telSess.send_string("\r\n\r\nUser Access Verification\r\n\r\nUsername: ")
	
    def shivaLanRoverWelcome(self):
        self.telSess.send_string("\xff\xfb\x01@ Userid: ")

    def jetDirectPrWelcome(self):
        self.telSess.send_string("\xff\xfc\x01\r\nHP JetDirect\r\n\r\n")

    def firstClassMsgWelcome(self):
        self.telSess.send_string("\x1b[H\x1b[2JYou have connected to a FirstClass System. Please login...\r\nUserID: ")

    def ambitCableRouterWelcome(self):
        self.telSess.send_string("\xff\xfa\x18\x01\xff\xf0\xff\xfb\x01\xff\xfb\x03Ambit Cable Router\r\n\r\nLogin: ")

    def nortelWelcome(self):
        self.telSess.send_string("\xff\xfb\x01\r\n")

    def arubaSwitchWelcome(self):
        self.telSess.send_string("\xff\xfb\x01\xff\xfb\x03\r\n(2017) \r\nUser: ")

    def busyboxWelcome(self):
        self.telSess.send_string("\xff\xfd\x01\xff\xfd\x1f\xff\xfd!\xff\xfb\x01\xff\xfb\x03\r\r\n(none) login: ")

    def customWelcome(self):
        self.telSess.send_string(config.get("custom_welcome"))
    
    def generateWelcome(self):
        switcher = {
            "default": [self.defaultWelcome,"Username: "],
            "custom": [self.customWelcome,config.get("custom_username")],
            "shivaLR": [self.shivaLanRoverWelcome,"@ Userid: "],
            "jetDirect": [self.jetDirectPrWelcome,None],
            "firstClassMsg": [self.firstClassMsgWelcome,"UserID: "],
            "ambitCable": [self.ambitCableRouterWelcome,"Login: "],
            "nortel": [self.nortelWelcome,None,"password: "],
            "arubaSwitch": [self.arubaSwitchWelcome,"User: "],
            "busybox": [self.busyboxWelcome,"login: "]
        }		
        type = switcher.get(config.get("device_welcome"), lambda: "Invalid type")
        type[0]()
        u = "N/A"
        if type[1] != None:
            u = self.telSess.recv_line()
            while filter(lambda x: x in string.printable, u) == '':
                self.telSess.send_string(type[1])
                u = self.telSess.recv_line()
        p = "Password: "
        if len(type) > 2:
            p = type[2]
        self.telSess.send_string(p)
        p = self.telSess.recv_line()
        self.telSess.session.login(u, p)