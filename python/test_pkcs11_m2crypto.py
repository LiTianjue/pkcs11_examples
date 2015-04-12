#!/bin/env python
import getpass
import StringIO
import io
import M2Crypto
import OpenSSL
import os
import PyKCS11
import sys

class CSPIDUtil():
	'''
	Requires M2Crypto patch discussed on following URL
	http://stackoverflow.com/questions/2195179/need-help-using-m2crypto-engine-to-access-usb-token
	also CAC card discussion
	http://stackoverflow.com/questions/10922133/error-for-m2crypto-https-get-thru-a-web-proxy-with-cac-card-authentication
	Seems to work with M2Crypto 22.3 per this checkin dated 2011-01-12
	https://github.com/martinpaljak/M2Crypto/commit/f0f3a1951a9809b642d0fb57f2285c7d38ee40de
	RHEL version is m2crypto-0.20.2-9.el6.x86_64
	Also difficulty installing M2Crypto on RedHat platforms fixed by checkin dated 2014-05-05
	https://github.com/martinpaljak/M2Crypto/commit/31aa7ffd869327475d622b951f57f24fce393688
	'''

	def __init__(self, pkcs11_lib_path, password=None):
		if not password:
			password = getpass.getpass()
		self.pykcs11_lib = PyKCS11.PyKCS11Lib()
		self.pykcs11_lib.load(pkcs11_lib_path)
		self.slots = self.pykcs11_lib.getSlotList()
		self.sessions = []
		for slot in self.slots:
			self.sessions.append(self.pykcs11_lib.openSession(slot))
		for session in self.sessions:
			session.login(password)
		self.pkcs11 = M2Crypto.Engine.load_dynamic_engine("pkcs11", "/usr/lib64/openssl/engines/engine_pkcs11.so")
		self.pkcs11.ctrl_cmd_string("MODULE_PATH", pkcs11_lib_path)
		self.pkcs11.ctrl_cmd_string("PIN", password)
		M2Crypto.m2.engine_init(M2Crypto.m2.engine_by_id('pkcs11'))

	def find_ids(self, object):
		ids = []
		for session in self.sessions:
			for attribute in session.getAttributeValue(object, [PyKCS11.CKA_ID]):
				buffer = StringIO.StringIO()
				for a_long in attribute:
					value = str(hex(a_long)).replace('0x','').replace('L','')
					if len(value) == 1:
						value = '0' + value
					buffer.write(value)
				
				id =  buffer.getvalue()
				ids.append((session.getSessionInfo().slotID, id))
		return ids

	def find_labels(self, object):
		labels = []
		for session in self.sessions:
			for attribute in session.getAttributeValue(object, [PyKCS11.CKA_LABEL]):
				labels.append((session.getSessionInfo().slotID,attribute))
		return labels

	def find_keys(self):
		keys = []
		for session in self.sessions:
			for object in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]):

				keys.append(object)
		return keys

	def get_openssl_slots_and_ids(self):
		results = []
		for key in self.find_keys():
			for (slot, id) in self.find_labels(key):
				results.append('slot_' + str(slot) + '-id_' + id)
		return results

	def find_m2crypto_x509s(self):
		self.m2crypto_x509s = []
		for id in self.get_openssl_slots_and_ids():
			self.m2crypto_x509s.append(self.pkcs11.load_certificate(id))
		return self.m2crypto_x509s

	def find_m2crypto_private_keys(self):
		self.m2crypto_keys = []
		for id in self.get_openssl_slots_and_ids():
			self.m2crypto_keys.append(self.pkcs11.load_private_key(id))
		return self.m2crypto_keys

	def __del__(self):
		for session in self.sessions:
			session.logout()
		M2Crypto.Engine.cleanup()

	def get_m2crypto_ssl_contexts(self):
		contexts = []
		ids = self.get_openssl_slots_and_ids()
		for id in ids:
			x509 = self.pkcs11.load_certificate(id)
			key = self.pkcs11.load_private_key(id)
			context = M2Crypto.SSL.Context(protocol='tlsv1')
			context.set_allow_unknown_ca(True)
			context.set_verify(M2Crypto.SSL.verify_none, True)
			context.load_verify_locations(capath=os.path.expanduser('~') + os.sep + '.testca')
			M2Crypto.m2.ssl_ctx_use_x509(context.ctx, x509.x509)
			M2Crypto.m2.ssl_ctx_use_pkey_privkey(context.ctx,key.pkey)
			contexts.append(context)
		return contexts

	
	def test_m2crypto_urllib2(self, url):
		for context in self.get_m2crypto_ssl_contexts():
			opener = M2Crypto.m2urllib2.build_opener(context)
			response = opener.open(url)
			print response.code
			print response.read()


def main():
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('--module',help='module shared library file',default='/opt/cspid/libcspid.so')
	parser.add_argument('-p','--pin',help='pkcs11 module slot pin')
	parser.add_argument('--key_labels',help='lists key labels',action='store_true')
	parser.add_argument('--key_ids',help='lists key ids',action='store_true')
	parser.add_argument('--openssl',help='lists key ids in openssl --cert format',action='store_true')
	parser.add_argument('--test',help='test',action='store_true')
	parser.add_argument('--url',help='url to use for --test',default='https://localhost.localdomain')
	args = parser.parse_args()
	if not (args.key_labels or args.key_ids or args.openssl or args.test):
		parser.print_help()
		return 'You must select either --key_labels or --key_ids or --openssl or --test'
	m = CSPIDUtil(args.module, password=args.pin)
	if args.key_labels:
		for key in m.find_keys():
			for label in m.find_labels(key):
				print label
	if args.key_ids:
		for key in m.find_keys():
			for id in m.find_ids(key):
				print id
	if args.openssl:
		for result in m.get_openssl_slots_and_ids():
			print result
	if args.test:
		m.test_m2crypto_urllib2(args.url)
	return 0
	

if __name__ == '__main__':
	sys.exit(main())
