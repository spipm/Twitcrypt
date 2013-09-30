'''
	Twitcrypt
	Encrypt/decrypt twitter API keys using Blowfish cipher
	'''

from Crypto.Cipher import Blowfish
from hashlib import md5, sha1, sha224
from getpass import getpass
from os.path import isfile, isdir
from os import mkdir


# directory for keys
d = 'twitkeys/'

# global variables voor iterations
iterations = 100
baserounds = 100	# increase for better but slower encryption


def getpassuser(line):
	'''
		Get user input for password
		Set iterations based on password
		Return hashed password
		''' 
	global iterations, baserounds

	passkey = getpass(line)
	l       = len(passkey)

	# cipher iterations based on password length
	iterations = l * baserounds

	# hash the password
	div 	= l / 2
	passkey = passkey[:div] + md5(passkey).hexdigest() + passkey[div:]
	for i in range(len(passkey)):
		passkey = sha1(passkey).hexdigest()		
	for i in range(iterations / (baserounds / 10)):
		passkey = sha224(passkey).hexdigest()

	return passkey

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
	global iterations
	
	l = 8 - len(key) % 8
	if l < 8:	key = key + (chr(l) * l)
	
	for i in range(iterations):	key = crypt.encrypt(key)
	return key

def newkeys(crypt):
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

def decryptkey(crypt, key):
	'''
		Decrypt encrypted key read from file
		'''
	for i in range(iterations):	key = crypt.decrypt(key)
	return stripchars(key)

def getapifiles(passkey):
	'''
		Return API keys from files
		'''
	crypt = Blowfish.new(passkey)
	if not isdir(d):
		mkdir(d)
		newkeys(crypt)
	if not isfile(d+'ckey.key') or not isfile(d+'csecret.key') or not isfile(d+'atkey.key') or not isfile(d+'atsecret.key'):
		newkeys(crypt)
	ckey 	= decryptkey(crypt, open(d+'ckey.key',	'rb').read())
	csecret = decryptkey(crypt, open(d+'csecret.key','rb').read())
	atkey 	= decryptkey(crypt, open(d+'atkey.key',	'rb').read())
	atsecret= decryptkey(crypt, open(d+'atsecret.key','rb').read())
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
