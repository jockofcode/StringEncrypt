#!/usr/bin/env ruby
# == Synopsis
# The encryption.rb library simplifies the creation and loading of RSA keys
# along with encrypting/decrypting strings using the RSA keys or AES-256 password
# with salt.  Encryption/Decryption is simplified by opening the String class with
# a encrypt and decrypt method and one for rsa keys (encryptr/decryptr) which are
# called automatically from the former methods if the password argument is an RSA
# key.  To reduce the size of the resulting encrypted file it can optionally be
# compressed before encryption using encryptz/decryptz methods.
# == Usage
# * encrypted_string = "string to encrypt with AES-256".encrypt("super secret password")
# * key = rsa_key(1024);
#   encrypted_string = "string to encrypt with rsa key".encryptr(key.public_key)
#   or
#   encrypted_string = "string to encrypt with rsa key".encrypt(key.public_key)
# * encrypted_string = "string to compress then encrypt".encryptz("super secret password")
# [Note] decryption is done with the corresponding decrypt/decryptr/decryptz methods.
# [Note] if you encrypted with a public key like above, you decrypt with the private (master) key
#        (either key or key.private_key).  If you encrypted with the private (master) key you can
#        decrypt with either the private or the public key (preferably the public key, but it's your choice)
# [Note] if the RSA key to use is in a file use: key = rsa_key("public_key_file.pub") or key = rsa_key("private_key_file.pub")
#
# == Author
# Branden Giacoletto, Carbondata Digital Services
#
# == Copyright
# Copyright (c) 2009 Carbondata Digital Services
# Licensed under the same terms as Ruby

require 'openssl'
require 'zlib'
require 'yaml'
# require 'base64'

# rsa key will either create a new RSA key if a bit size is supplied (multiples of 1024, 15 is supposed to be equivalent to AES-256) or
# the filename of an already created key.
# If a password is given then the rsa file will be decrypted.
def rsa_key(bitsize_or_filename,password = nil)
	if bitsize_or_filename.class.to_s == "String" && password == nil
		return OpenSSL::PKey::RSA.new(File.read(bitsize_or_filename))
	elsif bitsize_or_filename.class.to_s == "String" && password != nil
		return OpenSSL::PKey::RSA.new(File.read(bitsize_or_filename).decrypt(password))
	elsif bitsize_or_filename.class.to_s != "String" && password == nil then
			return OpenSSL::PKey::RSA.new(bitsize_or_filename)
	end
end

# Opens the String class providing encryption and zipping methods
class String
	@@magic = "Salted__"
	@@salt_len = 8
	# decrypts the string using either and string password or RSA key created with rsa_key()
	# =====example 
	# * <tt> "string to decrypt".decrypt("super secret password")</tt> # using a string for a password
	# * <tt> "string to decrypt".decrypt(key.public_key)</tt> # using the public key
	# * <tt> "string to decrypt".decrypt(key.private_key)</tt> # using the private key
	# * <tt> "string to decrypt".decrypt(key)</tt> # using the private key unless specifically loaded the public key
	#
	# if true is passed for the second argument then the string is decompressed after it is decrypted
	def decrypt(password = "", unzip_it = false)
		if password.class.to_s == "OpenSSL::PKey::RSA" then
			result = nil
			begin
				result = self.decryptr(password)
			rescue
				enc_password_size = self[0...6].to_i
				enc_password = self[6...(enc_password_size + 6)]
				message = self[(enc_password_size + 6)..-1]
				random_pass = (enc_password).decryptr(password)
				decrypted_data = message.decrypt(random_pass)
				result = decrypted_data
			end
			if unzip_it == true then result = result.unzip end
			return result
		end
		salt = ""
		if !self.is_encrypted?
			return nil # Salt is wrong
		end
		salt = self[(@@magic.length)...(@@salt_len+@@magic.length)]
		c = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
		c.decrypt
		c.pkcs5_keyivgen(password,salt,1)
		result = nil
		begin
			result = (c.update(self[@@salt_len+@@magic.length..-1]) + c.final)
			if unzip_it == true then result = result.unzip end
		rescue
			result = nil
		end
		return result
	end

	# encrypts the string using either and string password or RSA key created with rsa_key()
	# =====example 
	# * <tt> "string to encrypt".encrypt("super secret password")</tt> # using a string for a password
	# * <tt> "string to encrypt".encrypt(key.public_key)</tt> # using the public key
	# * <tt> "string to encrypt".encrypt(key.private_key)</tt> # using the private key
	# * <tt> "string to encrypt".encrypt(key)</tt> # using the private key unless specifically loaded the public key
	#
	# if true is passed for the second argument then the string is compressed before it is encrypted
	# =====note if an RSA key is provided for encryption but the string to be encrypted is too long, then a temporary, random AES-256 key is created to encrypt the string, then that password is encrypted with the RSA key
	def encrypt(password = "", zipit = false)
		if password.class.to_s == "OpenSSL::PKey::RSA" then
			result = nil
			begin
				result = (if zipit then self.zip else self end).encryptr(password)
			rescue
				enc_password_size = 0
				random_pass = OpenSSL::Random.random_bytes(117)
				rand_enc_password = (random_pass.encryptr(password))
				enc_password_size = rand_enc_password.length.to_s.ljust(6)
				result = enc_password_size + rand_enc_password + (if zipit then self.zip else self end).encrypt(random_pass)
			end
			return result
		end
		c = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
		salt = (0...(@@salt_len)).inject(""){ |carry,num| carry += rand(256).chr }
		c.encrypt
		c.pkcs5_keyivgen(password,salt,1)
		result = nil
		begin
			result = @@magic + salt + c.update(if zipit then self.zip else self end) + c.final
		rescue
			result = nil
		end
		# make sure it can be successfully decrypted
		if self.sha != result.decrypt(password,zipit).sha then result = nil end
		return result
	end

	# encrypts the string specifically with a RSA key.  Is called from encrypt if a key is passed for the password
	def encryptr(key)
		if (key.to_s =~ /^-----BEGIN (RSA|DSA) PRIVATE KEY-----$/).nil?
			return key.public_encrypt(self)
		else
			return key.private_encrypt(self)
		end
	end

	# decrypts the string specifically with a RSA key.  Is called from decrypt if a key is passed for the password
	def decryptr(key)
		if (key.to_s =~ /^-----BEGIN (RSA|DSA) PRIVATE KEY-----$/).nil?
			return key.public_decrypt(self)
		else
			begin
				result = nil
				result = key.private_decrypt(self)
			rescue
				result = key.public_decrypt(self)
			end
			return result
		end
	end

	# Returns the sha1 hash of the string as a character string
	def sha
		return OpenSSL::Digest::Digest.new('sha1',self).to_s
	end

	# checks for the salt string as the magic string at the beginning of the string.  If present then it must be encrypted.
	def is_encrypted?
		if self[0...(@@magic.length)] == @@magic
			return true
		else
			return false
		end
	end

	# compresses the string using zlib
	def zip
		return Zlib::Deflate.deflate(self,Zlib::BEST_COMPRESSION)
	end

	# decompresses the string that was previously compressed with zip
	def unzip
		return Zlib::Inflate.inflate(self)	
	end

	# compresses and encrypts the string	
	def encryptz(password="")
		return self.zip.encrypt(password)
	end

	# uncompresses and decrypts the string
	def decryptz(password="")
		return self.decrypt(password).unzip
	end
end
