#!/bin/env ruby
require "rubygems"
require "pkcs11"
require "openssl"
module TESTPKCS11
	class PKCS11Tester
		include PKCS11
		attr_accessor :pkcs11, :certs, :cert_labels, :key_labels, :e_pkcs11

		def initialize(mod_path, pin)
			@pin = pin
			@pkcs11 = PKCS11.open(mod_path)
			@certs = []
			@cert_labels = []
			@key_labels = []
			for slot in @pkcs11.active_slots
				session = slot.open(CKF_SERIAL_SESSION)
				session.login(:USER, pin)
				for private_key in session.find_objects(template={:CLASS => PKCS11::CKO_PRIVATE_KEY})
					slot_id = slot.to_int()
					label = private_key[:LABEL]
					openssl_id = 'slot_' + slot_id.to_s + '-id_' + label
					@key_labels.push(openssl_id)
				end
				for obj in session.find_objects(:CLASS => PKCS11::CKO_CERTIFICATE)
					label = obj[:LABEL]
					@cert_labels.push(label)
					cert = OpenSSL::X509::Certificate.new(obj[:VALUE])
					@certs.push(cert)
				end
				session.logout
			OpenSSL::Engine.load
			@e_pkcs11 = OpenSSL::Engine.by_id("dynamic"){|e|
				e.ctrl_cmd("SO_PATH", "/usr/lib64/openssl/engines/engine_pkcs11.so")
				e.ctrl_cmd("ID", "pkcs11")
				e.ctrl_cmd("LIST_ADD", "1")
				e.ctrl_cmd("LOAD")
				e.ctrl_cmd("MODULE_PATH", mod_path)
				#e.ctrl_cmd("VERBOSE")
			}
		end

		def test_get
			for key_label in key_labels
					e_pkcs11.ctrl_cmd("PIN", @pin)
				puts "using key " + key_label
				pkey = e_pkcs11.load_private_key(key_label)
				require "net/http"
				require "uri"
				uri = URI.parse("https://localhost.localdomain/")
				http = Net::HTTP.new(uri.host, uri.port)
				http.use_ssl = true
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.key = pkey
				# assuming it is the first cert now, but this may not always be true
				for cert in @certs
					cert_pub = cert.public_key
					key_pub = pkey.public_key
					if cert_pub.to_s == key_pub.to_s
						selected_cert = cert
						break
					end
				end
				http.cert = selected_cert
				request = Net::HTTP::Get.new(uri.request_uri)
				response = http.request(request)
				puts response.body
			end
		end
	end
end
require "highline/import"
pass = ask("Enter your password:  ") { |q| q.echo = "*" }
t = TESTPKCS11::PKCS11Tester.new("/opt/cspid/libcspid.so",pass)
t.test_get
end
