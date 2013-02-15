require 'net/https'
require 'net/http'
require 'rex/proto/http/client'    

class Metasploit3 < Msf::Auxiliary
	
	include Msf::Auxiliary::Badger_Report

	def initialize(info={})
		super( update_info( info,
		'Name'		=> 'Wigle.Net BSSID Lookup',
		'Description'	=> %q{
		This module can lookup a BSSID agains the Wigle.Net database
		},
		'License'	=> MSF_LICENSE,
		'Author'	=> ['v10l3nt']
		))        

		register_options([
			OptString.new('USER', [true, 'Wigle.net user account.']),
			OptString.new('PASS', [true, 'Wigle.net account password.']),
			OptString.new('BSSID', [true, 'BSSID to search for.']),
			],
		self.class)
	end	

	def query_wigle        
		c = Rex::Proto::Http::Client.new("wigle.net",443,{},true)
		req = c.request_cgi(
			'method'		=> 'GET',
			'uri'			=> '/gps/gps/main/login',
			'vars_get'		=> { 'credential_0' => datastore['USER'], 'credential_1' => datastore['PASS'] }
			)
		resp = c.send_recv(req, 500)
		if (resp.code != 200)
			raise RuntimeError, "Wigle.Net responded with error: #{resp.code}"
		else
			print_status("Logged Into Wigle.Net Succesfully")
			headers = "#{resp.headers}"            
			cookie = headers.slice(headers.index('auth='),headers.length)
			cookie = cookie.slice(0,cookie.index(';')+1)
		end                         
		req = c.request_cgi(
			'method'		=> 'POST',
			'uri'			=> '/gps/gps/main/confirmquery/',
			'vars_get'		=> { 'netid' => datastore['BSSID'] },
			'headers'      =>	{'Cookie'       => cookie,}
			)
		resp = c.send_recv(req, 500)                         
		if (resp.code != 200)
			raise RuntimeError, "Wigle.Net responded with error: #{resp.code}"
		else
			results = resp.body
			if results.include? 'too many queries'
				return 'Query rate exceeded.'
			end            
			if results =~ /(maplat=(.)+&maplon)/
				lat=$1
				lat=lat.sub("maplat=","").chomp("&maplon")
			else
				lat="N/A"
			end
			if results =~ /(maplon=(.)+&mapzoom)/
				lon=$1
				lon=lon.sub("maplon=","").chomp("&mapzoom")
			else
				lon="N/A"
			end
			geoCoords = "#{lat}, #{lon}"
			if geoCoords.include? "N/A"
				geoCoords="BSSID not found in Wigle.Net"
			else
				print geoCoords
			end
		end      
	end       

	def run
		pos=wigle_search(datastore['USER'],datastore['PASS'],datastore['BSSID'])
		if pos!= nil
			print_status("Geolocated BSSID #{datastore['BSSID']}, Lat = #{pos.lat}, Lon = #{pos.lon}, Acc = #{pos.acc}")
			report_results(pos,"msf_wigle","BSSID: #{datastore['BSSID']}")
		else
			print_status("Did not find bssid in Wigle.Net Database")
		end
	end
end
