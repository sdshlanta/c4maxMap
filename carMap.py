import telnetlib
import shodan
import json
from lxml import etree
from pykml.factory import KML_ElementMaker as KML
import time

SHODAN_API_KEY = ""

def degreeConvert(degrees, direction):
	deg_min, dmin = degrees.split('.')
	degrees = int(deg_min[:-2])
	minutes = float('%s.%s' % (deg_min[-2:], dmin))
	decimal = degrees + (minutes/60)
	if direction.lower() == 'n' or direction.lower() == 'e':
		return str(decimal)
	else:
		return str(-decimal)

def main():
	while True:
		try:
			god = shodan.Shodan(SHODAN_API_KEY)

			queryResults = god.search('port:23 gps "on console"')
			fld = KML.Folder()
			for result in queryResults['matches']:
				ip = result['ip_str']
				print "%s" % ip

				try:
					telnet = telnetlib.Telnet(ip,23,3)
					print 'connected'
					telnet.read_until('Basics[', 5)
					telnet.write("gpspos\n")
					GPGGA = telnet.read_until('Basics[',5)
					telnet.close()
					#print GPGGA
					GPGGA = GPGGA.split("$GPGGA")[1].split(',')
					lat = degreeConvert(GPGGA[2], GPGGA[3])
					lon = degreeConvert(GPGGA[4], GPGGA[5])
					lonLat = lon +','+ lat
					pm = KML.Placemark(
							KML.name(ip),
							KML.Point(
								KML.coordinates(lonLat)
								)
							)
					#print etree.tostring(pm, pretty_print=True)
					fld.append(pm)
					print "data aquired"

				except Exception as e:
					print e
					continue
			f = file(str(time.time()).split('.')[0]+'.kml', 'w')
			f.write(etree.tostring(fld, pretty_print=True))
			f.close()
			print "file generated"

		except shodan.APIError as e:
			print e
			continue

if __name__ == '__main__':
	main()