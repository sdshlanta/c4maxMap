
from __future__ import print_function
import argparse
print = lambda x: sys.stdout.write("%s\n" % x)
parser = argparse.ArgumentParser(description="Finds TGUs and maps them.")
parser.add_argument('-K', action='store_true', default=False, help="Specifies the output as KML, the default is HTML")
parser.add_argument('-H', action='store_true', default=True, help="Specifies the output as HTML, this is the default option.")
parser.add_argument('-f', type=str, default=None, help='Specifies the filename that should be used. If none is specified the current unix timestamp is used instead')
parser.add_argument('-d', action='store_true', default=False, help='activates debug mode which increses the verbosity of the printed messages')
parser.add_argument('-s', type=str, default=None, help='Specifies the use of the Shodan API, please supply your API key as an argument')
parser.add_argument('-c', type=str, default=None, nargs=2, help='Specifies the use of the Censys API, please supply your API key as an argument. Due to the paged nature of the API this will take some time...')
parser.add_argument('-t', type=int, default=4, help='Specifies the number of threads that should be used for scanning, defaults to 4.')
parser.add_argument('-r', action='store_true', default=False, help='Specifies that IP addresses should be retried at a later time if the connection failes.')
args = parser.parse_args()
if args.s == None and args.c == None:
	print('Please specify the use of either the Shodan or Censys API.')
	exit()
import telnetlib
import shodan 
import json
from lxml import etree
from pykml.factory import KML_ElementMaker as KML
import time
from bs4 import BeautifulSoup
import requests
import threading
import queue
import sys

running = True
fld = KML.Folder()
IPqueue = queue.Queue(maxsize=0)
outQueue = queue.Queue(maxsize=0)

def degreeConvert(degrees, direction):
	deg_min, dmin = degrees.split('.')
	degrees = int(deg_min[:-2])
	minutes = float('%s.%s' % (deg_min[-2:], dmin))
	decimal = degrees + (minutes/60)
	if direction.lower() == 'n' or direction.lower() == 'e':
		return str(decimal)
	else:
		return str(-decimal)

def telRequest(ip):
	telnet = telnetlib.Telnet(ip,23,5)
	telnet.read_until('Basics[', 5)
	telnet.write("gpspos\n")
	GPGGASentence = telnet.read_until('Basics[',5)
	telnet.close()
	return GPGGASentence

class htmlBulider(object):
	"""docstring for htmlBulider"""
	def __init__(self):
		super(htmlBulider, self).__init__()
		self.html=BeautifulSoup(file('index.html','r'), 'html.parser')
	def addToHtml(self, ip, lonLat):
		scripStart = self.html.script.string[:116]
		scriptEnd = self.html.script.string[116:]
		self.html.script.string = scripStart + u"var " + 'a' + str(time.time()).split('.')[0] + u" = new google.maps.Marker({position:{lat: " + lonLat[1] + u", lng: " + lonLat[0] + u"},map:map,title: '" + ip + u"'});" + scriptEnd
		if args.d:
			print(self.html.script)
	def getHTMLString(self):
		return self.html.prettify()

class kmlBulider(object):
	"""docstring for kmlBulider"""
	def __init__(self):
		super(kmlBulider, self).__init__()
	def addToKML(self, ip, lonLat):
		pm = KML.Placemark(
		KML.name(ip),
			KML.Point(
				KML.coordinates(lonLat[0]+','+lonLat[1])
				)
			)
		if args.d:
			print(etree.tostring(pm, pretty_print=True))
		fld.append(pm)
	def getKMLString(self):
		return etree.tostring(fld)
	
class censys(object):
	"""docstring for censys"""
	def __init__(self, censysApiKey):
		super(censys, self).__init__()
		self.censysApiKey = censysApiKey
		self.API_URL = "https://www.censys.io/api/v1"
	def search(self, searchQuery):
		ips = set()
		if self.censysApiKey == None:
				return ips
		pages = float('inf')
		page = 1
		print("Press ctrl+c to proceed with data currently aquired")
		while page <= pages:
			try:
				
				params = {'query' : searchQuery, 'page' : page}
				res = requests.post(self.API_URL + "/search/ipv4", json = params, auth = (self.censysApiKey[0], self.censysApiKey[1]))
				payload = res.json()

				
				for result in payload['results']:
					ips.add(result['ip'])
				pages = payload['metadata']['pages']
				print('Page ' + str(page) + ' of ' + str(pages) + ' (' + str(len(ips)) + ' IPs from Censys so far.)')
				page+=1
				#because the api is rate limited to 120 requests per 5 min which works out to one request ever 2.5 seconds.
				time.sleep(2.5)
			except KeyboardInterrupt as e:
				break
			except Exception as e:
				if args.d:
					print(e)
					print(json.dumps(payload))
				continue
			
		return ips

class APIRequests(object):
	"""docstring for APIRequests"""
	def __init__(self, shodanApiKey, censysApiKey):
		super(APIRequests, self).__init__()
		self.god = None
		self.Censys = None
		self.previous = set()
		if shodanApiKey != None:
			try:
				self.god = shodan.Shodan(shodanApiKey)
			except shodan.APIError as e:
				print(e)
		self.Censys = censys(censysApiKey)
	def search(self, searchQuery):
		ips = set()
		if self.god != None:
			shodanResults = self.god.search(searchQuery)
			for result in shodanResults['matches']:
				ips.add(result['ip_str'])
		current = ips|self.Censys.search(searchQuery)
		difference = current - self.previous
		if len(difference) == 0:
			global running
			running = False
		print('~' + str(IPqueue.qsize()+len(difference)) + ' IPs to test')
		for ip in difference:
			IPqueue.put(ip,True)
		self.previous = current|self.previous


class mapper(object):
	"""docstring for mapper"""
	def __init__(self):
		super(mapper, self).__init__()
	def run(self):
		t = threading.Thread(target=self.mapify)
		t.start()
		return t
	def mapify(self):
		while running:
			while not IPqueue.empty() and running:
				try:
					ip = IPqueue.get(True, 1)
					#print(ip)
					GPGGASentence = telRequest(ip)
					if args.d:
						print(GPGGASentence)
					GPGGASentence = GPGGASentence.split("$GPGGA")[1].split(',')
					lat = degreeConvert(GPGGASentence[2], GPGGASentence[3])
					lon = degreeConvert(GPGGASentence[4], GPGGASentence[5])
					print(ip +'\nConnected\nData aquired')
					outQueue.put((ip, (lon, lat)), True)
				except IndexError as e:
					print(ip+'\nConnected\nUnsupported NEMA sentence.')
					continue
				except Exception as e:
					if args.d:
						print(ip)
						raise e
					else:
						print(ip + '\n' + str(e))
						if args.r:
							IPqueue.put(ip,True)
					continue
				
			while IPqueue.empty() and running:
				pass


def main():
	global running

	if args.H:
		HTMLBldr = htmlBulider()
		fileExtention='.html'

	if args.K:
		fileExtention='.kml'
		KMLBldr = kmlBulider()

	APIRequester = APIRequests(args.s,args.c)
	APIRequester.search('port:23 gps "[1m[35mWelcome on console"')
	threads = []

	for x in xrange(args.t):
		threads.append(mapper().run())
	for hurp in threads:
		print(hurp)

	while running:
		while not IPqueue.empty() and running:
			try:
				ip, lonLat = outQueue.get(True,1)
				if args.K:
					KMLBldr.addToKML(ip, lonLat)
				if args.H:
					HTMLBldr.addToHtml(ip, lonLat)
			except KeyboardInterrupt:
				print("Allowing threads to finish up, this should take 30 seconds at most")
				running = False
				for thread in threads:
					thread.join()
				while not outQueue.empty():
					ip, lonLat = outQueue.get(True,1)
					if args.K:
						KMLBldr.addToKML(ip, lonLat)
					if args.H:
						HTMLBldr.addToHtml(ip, lonLat)
				continue
			except queue.Empty:
				continue
			except Exception as e:
				if args.d:
					print(e)
				continue
		if running:
			APIRequester.search('port:23 gps "on console"')
	try:
		IPqueue
		for thread in threads:
			try:
				thread.join()
			except Exception as e:
				continue
		while not outQueue.empty():
			ip, lonLat = outQueue.get(True,1)
			if args.K:
				KMLBldr.addToKML(ip, lonLat)
			if args.H:
				HTMLBldr.addToHtml(ip, lonLat)
		if args.f == None:
			f = file(str(time.time()).split('.')[0]+fileExtention, 'w')
		else:
			f = file(args.f, 'w')
		if args.K:
			f.write(KMLBldr.getKMLString())
		if args.H:
			f.write(HTMLBldr.getHTMLString())
		f.close()
		print("file generated")
	except Exception as e:
		raise e

if __name__ == '__main__':
	running = True
	main()