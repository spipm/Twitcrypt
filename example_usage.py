'''
	Example usage of twitcrypt
	Get user timeline
	'''

import twitter
from twitcrypt import twitcrypt

ckey, csecret, atkey, atsecret = twitcrypt.getkeys()

try:
	api = twitter.Api(consumer_key = ckey, consumer_secret = csecret, access_token_key = atkey, access_token_secret = atsecret) 
	feeds = api.GetUserTimeline()
except:
	print 'Error using twitter API, got the right password?'
	exit(0)

for thing in feeds:
	print thing