import requests
import time
import db
import Queue

USER_AGENT = "Telnet Honeybot Backend"


class QuotaExceededError(Exception):		
	def __str__(self):
		return "QuotaExceededError: Virustotal API Quota Exceeded"

class Virustotal:
	def __init__(self, key):
		self.api_key    = key
		self.url        = "https://www.virustotal.com/vtapi/v2/"
		self.headers 	= { "User-Agent" : USER_AGENT }
		self.engines    = ["DrWeb", "Kaspersky", "ESET-NOD32"]
		
		self.queue      = Queue.Queue()
		self.timeout    = 0

	def req(self, method, url, files=None, params=None, headers=None):
		print "VT " + url
		r = None
		if method == "GET":
			r = requests.get(url, files=files, params=params, headers=headers)
		elif method == "POST":
			r = requests.post(url, files=files, params=params, headers=headers)
		else:
			raise ValueError("Unknown Method: " + str(method))

		if r.status_code == 204:
			raise QuotaExceededError()
		else:
			return r

	def upload_file(self, f, fname):
		fp      = open(f, 'rb')
		params  = {'apikey': self.api_key}
		files   = {'file': (fname, fp)}
		res     = self.req("POST", self.url + 'file/scan', files=files, params=params, headers=self.headers)
		json    = res.json()
		fp.close()
		
		if json["response_code"] == 1:
			return json
		else:
			return None

	def query_hash_sha256(self, h):
		params  = { 'apikey': self.api_key, 'resource': h }
		res     = self.req("GET", self.url + "file/report", params=params, headers=self.headers)

		json = res.json()

		if json["response_code"] == 1:
			return json
		else:
			return None

	def put_comment(self, obj, msg):
		params  = { 'apikey': self.api_key, 'resource': obj, "comment": msg }
		res     = self.req("GET", self.url + "comments/put", params=params, headers=self.headers)
		json    = res.json()

		if json["response_code"] == 1:
			return json
		else:
			return None
		
	def get_best_result(self, r):
		if r["scans"]:
			for e in self.engines:
				if r["scans"][e] and r["scans"][e]["detected"]:
					return r["scans"][e]["result"]
			for e,x in r["scans"].iteritems():
				if x["detected"]:
					return x["result"]
			return None
		else:
			return None

	def query_ip_reports(self, ip):
		params  = { 'apikey': self.api_key, 'ip': ip }
		res     = self.req("GET", self.url + "ip-address/report", params=params, headers=self.headers)

		json = res.json()

		if json["response_code"] == 1:
			return json
		else:
			return None

	def query_domain_reports(self, domain):
		params  = { 'apikey': self.api_key, 'domain': domain }
		res     = self.req("GET", self.url + "domain/report", params=params, headers=self.headers)

		json = res.json()

		if json["response_code"] == 1:
			return json
		else:
			return None