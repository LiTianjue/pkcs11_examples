#!/bin/env python
import argparse
import getpass
import httplib_example
import logging
from nss.error import NSPRError
import nss.io
import nss.nss
import nss.ssl
import os
import pycurl
import sys

class TestNss():

	def password_callback(self, slot, password):
		if password:
			self.password = password
		else:
			self.password = getpass.getpass()
		return self.password

	def __init__(self):
		self.cacerts = []
		self.usercerts = []
		self.keys = []
		nss.nss.nss_init('.')
		nss.nss.set_password_callback(self.password_callback)
		self.certdb = nss.nss.get_default_certdb()
		self.certs = nss.nss.list_certs(0)
		for cert in self.certs:
			if cert.is_ca_cert():
				self.cacerts.append(cert)
			else:
				self.usercerts.append(cert)
				self.keys.append(nss.nss.find_key_by_any_cert(cert))
				if 'localhost' in cert.subject:
					self.localhost = cert
				else:
					self.cert = cert
		self.key = self.keys[0]
		self.certdb = nss.nss.get_default_certdb()
		self.nicknames = nss.nss.get_cert_nicknames(self.certdb, nss.nss.SEC_CERT_NICKNAMES_USER)
		for nickname in self.nicknames:
			if 'localhost' in nickname:
				self.localhost_nickname = nickname
			else:
				self.client_nickname = nickname

	def test_httplib(self):
		print self.client_nickname
		logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M')
		conn = httplib_example.NSSConnection(host='localhost.localdomain',port=443,dbdir='.',nickname=self.client_nickname, password=self.password)
		conn.connect()
		conn.request("GET", "/")
		response = conn.getresponse()
		print "status = %s %s" % (response.status, response.reason)
		headers = response.getheaders()
		print "headers:"
		for header in headers:
			print "%s: %s" % (header[0], header[1])
		content_length = int(response.getheader('content-length'))
		data = response.read()
		assert(content_length == len(data))
		print data
		conn.close()

	def find_cert_by_nickname(self, nickname):
		return nss.nss.find_cert_from_nickname(nickname)

	def find_key_by_nickname(self, nickname):
		cert = self.find_cert_by_nickname(nickname)
		if cert:
			return nss.nss.find_key_by_any_cert(cert)

	def test_pycurl(self):
		os.environ['SSL_DIR'] = '.'
		curl = pycurl.Curl()
		curl.setopt(pycurl.SSLCERT, self.client_nickname)
		curl.setopt(pycurl.CAINFO, '/etc/pki/tls/certs/ca-bundle.crt')
		curl.setopt(pycurl.SSLCERTPASSWD, 'a')
		curl.setopt(pycurl.URL, 'https://localhost.localdomain')
		curl.perform()
		

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--nicknames',help='list nicknames',action='store_true')
	parser.add_argument('-n','--nickname', help='specify nickname',default=None)
	parser.add_argument('--pycurl', help='test pycurl',action='store_true')
	parser.add_argument('--httplib', help='test httplib',action='store_true')
	args = parser.parse_args()
	if not (args.nicknames or args.nickname or args.pycurl or args.httplib):
		sys.exit(parser.print_help())
	t = TestNss()
	if args.nicknames:
		for nickname in t.nicknames:
			print nickname
	if args.nickname:
		print t.find_cert_by_nickname(args.nickname)
		print t.find_key_by_nickname(args.nickname)
	if args.pycurl:
		t.test_pycurl()
	if args.httplib:
		t.test_httplib()
	return 0

if __name__ == '__main__':
	sys.exit(main())
