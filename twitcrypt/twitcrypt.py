'''
	Twitcrypt
	Encrypt/decrypt twitter API keys using Blowfish cipher
	'''

from Crypto.Cipher import Blowfish
from getpass import getpass
from os.path import isfile, isdir
from os import mkdir

# directory for keys
d = 'twitkeys/'

def getpassuser(line):
	'''
		Get user input for password
		''' 
	return getpass(line)

def getapiuser():
	'''
		Get API keys from user
		'''
	ckey 	= getpass('Enter consumer key >')
	csecret = getpass('Enter consumer secret >')
	atkey 	= getpass('Enter access token key >')
	atsecret= getpass('Enter access token secret >')
	return ckey, csecret, atkey, atsecret
	
def padcrypt(crypt, key):
	'''
		Add padding and return some key encrypted
		'''
	l = 8 - len(key) % 8
	if l < 8:	key = key + (chr(l) * l)
	return crypt.encrypt(key)

def newkeys(crypt, passkey):
	'''
		Save new API keys encrypted
		'''
	ckey, csecret, atkey, atsecret = getapiuser()
	open(d+'ckey.key',	'wb').write(padcrypt(crypt, ckey))
	open(d+'csecret.key',	'wb').write(padcrypt(crypt, csecret))
	open(d+'atkey.key',	'wb').write(padcrypt(crypt, atkey))
	open(d+'atsecret.key',	'wb').write(padcrypt(crypt, atsecret))
	return True
	

def stripchars(charkey):
	'''
		Strip padding characters
		'''
	return charkey.strip('\x01\x02\x03\x04\x05\x06\x07')

def getapifiles(passkey):
	'''
		Return API keys from files
		'''
	crypt = Blowfish.new(passkey)
	if not isdir(d):
		mkdir(d)
		newkeys(crypt, passkey)
	if not isfile(d+'ckey.key') or not isfile(d+'csecret.key') or not isfile(d+'atkey.key') or not isfile(d+'atsecret.key'):
		newkeys(crypt, passkey)
	ckey 	= stripchars(crypt.decrypt(open(d+'ckey.key',	'rb').read()))
	csecret = stripchars(crypt.decrypt(open(d+'csecret.key','rb').read()))
	atkey 	= stripchars(crypt.decrypt(open(d+'atkey.key',	'rb').read()))
	atsecret= stripchars(crypt.decrypt(open(d+'atsecret.key','rb').read()))
	return ckey, csecret, atkey, atsecret

def getkeys():
	'''
		Get user input and return decrypted keys
		'''
	passkey = getpassuser('Enter password >')
	return getapifiles(passkey)


def example_resetkeys():
	'''
		Example function to reset the password
		'''
	passkey = getpassuser('Enter old password >')
	ckey, csecret, atkey, atsecret = getapifiles(passkey)
	passkey = getpassuser('Enter new password >')
	crypt 	= Blowfish.new(passkey)
	open(d+'ckey.key',	'wb').write(padcrypt(crypt, ckey))
	open(d+'csecret.key',	'wb').write(padcrypt(crypt, csecret))
	open(d+'atkey.key',	'wb').write(padcrypt(crypt, atkey))
	open(d+'atsecret.key',	'wb').write(padcrypt(crypt, atsecret))
	print 'Changed password'
