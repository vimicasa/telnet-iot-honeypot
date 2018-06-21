
import requests
import time

from base import Proc

class Wget(Proc):
    
    def dl(self, env, url, path=None, echo=True):
        host = "hostname.tld"
        ip   = "172.217.16.227"
        date = time.strftime("%Y-%m-%d %H:%M:%S")
        if echo:
            env.write("--"+date+"--  " + url + "\n")
            env.write("Resolving "+host+" ("+host+")... "+ip+"\n")
            env.write("Connecting to  "+host+" ("+host+")["+ip+"]:80...")

        hdr = { "User-Agent" : "Wget/1.15 (linux-gnu)" }
        r = requests.get(url, stream=True, timeout=5.0, headers=hdr)

        data = ""
        for chunk in r.iter_content(chunk_size = 4096):
            data = data + chunk

        if path == None:
            path = url.split("/")[-1].strip()
        if path == "":
            path = "index.html"

        if echo:
            lenData = str(len(data))
            lenDataK = str(len(data)/1024)
            env.write(" connected\nHTTP request sent, awaiting response... 200 OK\n")
            env.write("Length: "+lenData+ "("+lenDataK+"K)" +" [text/html]\n")
            env.write("Saving to: '"+path+"'\n\n")
            env.write(path+"                                [ <=====>                                                                        ] "+lenDataK+"  --.-KB/s    in 1,7s\n\n")
            env.write(date+" (1,83 MB/s) - '"+path+"' saved ["+lenData+"/"+lenData+"]\n")

        info = ""
        for his in r.history:
            info = info + "HTTP " + str(his.status_code) + "\n"
            for k,v in his.headers.iteritems():
                info = info + k + ": " + v + "\n"
                info = info + "\n"

        info = info + "HTTP " + str(r.status_code) + "\n"
        for k,v in r.headers.iteritems():
            info = info + k + ": " + v + "\n"

        env.writeFile(path, data)
        env.action("download", {
            "url":  url,
            "path": path,
            "info": info
        })

    def run(self, env, args):
        if len(args) == 0:
            env.write("""BusyBox v1.22.1 (Ubuntu 1:1.22.0-19ubuntu2) multi-call binary.

Usage: wget [-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document FILE]
	[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]
	[-U|--user-agent AGENT] URL...

Retrieve files via HTTP or FTP

	-s	Spider mode - only check file existence
	-c	Continue retrieval of aborted transfer
	-q	Quiet
	-P DIR	Save to DIR (default .)
	-O FILE	Save to FILE ('-' for stdout)
	-U STR	Use STR for User-Agent header
	-Y	Use proxy ('on' or 'off')

""")
            return 1
        else:
            echo = True
            for arg in args:
                if arg == "-O":
                    echo = False
            for url in args:
                if url.startswith("http"):
                    self.dl(env, url, echo=echo)
                else:
                    self.dl(env, "http://"+url, echo=echo)
            return 0

Proc.register("wget", Wget())
