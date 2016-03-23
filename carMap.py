import telnetlib
import shodan 
import json
from lxml import etree
from pykml.factory import KML_ElementMaker as KML
import time
import argparse
from bs4 import BeautifulSoup
import requests
import threading
import queue

fld = KML.Folder()

IPqueue = queue.Queue(maxsize=0)

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
	try:
		telnet = telnetlib.Telnet(ip,23,3)
		print('Connected')
		telnet.read_until('Basics[', 5)
		telnet.write("gpspos\n")
		GPGGASentence = telnet.read_until('Basics[',5)
		telnet.close()
		return GPGGASentence
	except Exception as e:
		raise e

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
		if self.censysApiKey == None:
				return set()
		
		pages = float('inf')
		page = 1
		while page <= pages:
			try:
				print('Page: ' + str(page))
				params = {'query' : searchQuery, 'page' : page}
				res = requests.post(self.API_URL + "/search/ipv4", json = params, auth = (self.censysApiKey[0], self.censysApiKey[1]))
				payload = res.json()
				ips = set()
				for result in payload['results']:
					ips.add(result['ip'])
				pages = payload['metadata']['pages']
				page+=1
				time.sleep(1)
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
		try:
			self.god = shodan.Shodan(shodanApiKey)
		except shodan.APIError as e:
			print(e)
		self.Censys = censys(censysApiKey)
	def search(self, searchQuery):
		shodanResults = self.god.search(searchQuery)
		ips = set()
		for result in shodanResults['matches']:
			ips.add(result['ip_str'])
		for ip in ips|self.Censys.search(searchQuery):
			IPqueue.put(ip,True)

def main():
	if args.H:
		HTMLBldr = htmlBulider()
		fileExtention='.html'

	if args.K:
		fileExtention='.kml'
		KMLBldr = kmlBulider()

	APIRequests(args.s,args.c).search('port:23 gps "on console"')

	while True:
		try:
			while not IPqueue.empty():
				try:
					ip = IPqueue.get(True, 3)
					print("%s" % ip)
					GPGGASentence = telRequest(ip)
					if args.d:
						print(GPGGASentence)
					GPGGASentence = GPGGASentence.split("$GPGGA")[1].split(',')
					lat = degreeConvert(GPGGASentence[2], GPGGASentence[3])
					lon = degreeConvert(GPGGASentence[4], GPGGASentence[5])
					lonLat = (lon,lat)
					if args.K:
						KMLBldr.addToKML(ip, lonLat)
					if args.H:
						HTMLBldr.addToHtml(ip, lonLat)
					print("data aquired")
				except KeyboardInterrupt:
					raise
				except Exception as e:
					print(e)
					continue
			try:
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
		except shodan.APIError as e:
			print(e)
			continue

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="Finds TGUs and maps them.")
	parser.add_argument('-K', action='store_true', default=False, help="Specifies the output as KML, the default is HTML")
	parser.add_argument('-H', action='store_true', default=True, help="Specifies the output as HTML, this is the default option.")
	parser.add_argument('-f', type=str, default=None, help='Specifies the filename that should be used. If none is specified the current unix timestamp is used instead')
	parser.add_argument('-d', action='store_true', default=False, help='activates debug mode which increses the verbosity of the printed messages')
	parser.add_argument('-s', type=str, default=None, help='Specifies the use of the Shodan API, please supply your API key as an argument')
	parser.add_argument('-c', type=str, default=None, nargs=2, help='Specifies the use of the Censys API, please supply your API key as an argument. Due to the paged nature of the API this will take some time...')
	args = parser.parse_args()
	if args.s == None and args.c == None:
		print('Please specify the use of either the Shodan or Censys API.')
		exit()
	main()