import telnetlib
import shodan 
import json
from lxml import etree
from pykml.factory import KML_ElementMaker as KML
import time
import argparse
from bs4 import BeautifulSoup

SHODAN_API_KEY = ""
fld = KML.Folder()


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
		self.html.script.string = self.html.script.string[:116]+ u"var " + 'a' + str(time.time()).split('.')[0] + u" = new google.maps.Marker({position:{lat: " + lonLat[1] + u", lng: " + lonLat[0] + u"},map:map,title: '" + ip + u"'});" + self.html.script.string[116:]
		print(self.html.script)
	def getHTMLString(self):
		return self.html.prettify()


class kmlBulider(object):
	"""docstring for kmlBulider"""
	def __init__(self):
		super(kmlBulider, self).__init__()
		self.KMLFld = KML.Folder()
	def addToKML(self, ip, lonLat):
		pm = KML.Placemark(
		KML.name(ip),
			KML.Point(
				KML.coordinates(lonLat[0]+','+lonLat[1])
				)
			)
		#print(etree.tostring(pm, pretty_print=True))
		fld.append(pm)
	def getKMLString(self):
		return etree.tostring(self.KMLFld)
	
def main():
	if args.H:
		HTMLBldr = htmlBulider()
		fileExtention='.html'

	if args.K:
		fileExtention='.kml'
		KMLBldr = kmlBulider()
	while True:
		try:
			god = shodan.Shodan(SHODAN_API_KEY)

			queryResults = god.search('port:23 gps "on console"')
			for result in queryResults['matches']:
				ip = result['ip_str']
				print("%s" % ip)

				try:
					GPGGASentence = telRequest(ip)
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

				except Exception as e:
					print e
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
	parser.add_argument('-K', action='store_true', default=False, help="Specifies the output as KML, this or HTML output is required for program excution.")
	parser.add_argument('-H', action='store_true', default=False, help="Specifies the output as HTML, this or KML output is required for program excution.")
	parser.add_argument('-f', type=str, default=None, help='Specifies the filename that should be used. If none is specified the current unix timestamp is used instead')
	args = parser.parse_args()
	if args.K==False and args.H==False:
		print("Please specify a either HTML or KML")
		exit()

	main()