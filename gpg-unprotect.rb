#!/usr/bin/env ruby

require 'openssl'
require 'digest/sha1'

PASSPHRASE = # TODO

ARGF.binmode

tag = ARGF.readbyte

body_length = ARGF.readbyte
body = ARGF.read(body_length).bytes

# "A one-octet version number (4)"
version = body.shift

# "A four-octet number denoting the time that the key was created"
timestamp = body.shift(4).pack('C*').unpack('N').shift

# "A one-octet number denoting the public-key algorithm of this key"
pubkey_algo = body.shift

raise unless pubkey_algo == 18

# "a variable length field containing a curve OID"
oid_length = body.shift
oid = body.shift(oid_length)

# "MPI of an EC point representing a public key Q"
pubkey_length = body.shift(2).pack('C*').unpack('n').shift
pubkey = body.shift((pubkey_length + 7) / 8)

# "a variable-length field containing KDF parameters"
kdf_length = body.shift
kdf = body.shift(kdf_length)

# "One octet indicating string-to-key usage conventions"
s2k_usage = body.shift

raise unless s2k_usage == 254 || s2k_usage == 255

# "a one-octet symmetric encryption algorithm"
s2k_symkey_algo = body.shift

raise unless s2k_symkey_algo == 7

# "a string-to-key specifier"
s2k_specifier = body.shift

raise unless s2k_specifier == 0x03

# "hash algorithm"
s2k_hash_algo = body.shift

raise unless s2k_hash_algo == 2

# "8-octet salt value"
s2k_salt = body.shift(8).pack('C*')

# "count, a one-octet, coded value"
s2k_count = ->(count) { (16 + (count & 15)) << ((count >> 4) + 6) }.call(body.shift)

# "an Initial Vector (IV) of the same length as the cipher's block size"
s2k_iv = body.shift(16).pack('C*')

###

s2k_hash_input = s2k_salt + PASSPHRASE

s2k_hash = Digest::SHA1.new

iterations = 0

until (iterations + s2k_hash_input.size) > s2k_count
  s2k_hash.update(s2k_hash_input)
  iterations += s2k_hash_input.size
end

s2k_hash.update s2k_hash_input.slice(0, (s2k_count - iterations))
iterations += s2k_hash_input.slice(0, (s2k_count - iterations)).size

###

s2k_key = s2k_hash.digest.slice(0, 16)

aes = OpenSSL::Cipher::AES128.new(:CFB).decrypt
aes.key = s2k_key
aes.iv = s2k_iv

plain = (aes.update(body.pack('C*')) + aes.final).bytes

###

sha1 = plain.pop(20).pack('C*')

p Digest::SHA1.digest(plain.pack('C*'))

p plain

