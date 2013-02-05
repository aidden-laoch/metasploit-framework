require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	Rank = GreatRanking

	include Msf::Exploit::Remote::SMTPDeliver
	include Msf::Auxiliary::Badger_Report


	def initialize(info = {})
		super(update_info(info,
			'Name'		=> 'SMTP Image Link Emailer (Badger)',
			'Description'	=> %q{
			This module can be used to send an email with a embedded image link that 
			gets automatically rendered by some email clients. 
			},
			'License'	=> MSF_LICENSE,
			'Author'	=> ['v10l3nt']
		))        
		register_options([OptString.new('BODY', [true, 'Message Body', 'Honey Badger dont give a ....'])],
			self.class)

	end

	def run
        uri = return_uri
		reporting_uri = "#{uri}?target=#{datastore['BADGER_TGT']}&agent=msf_smtpimg"

		html = "<html><head><title>#{datastore['SUBJECT']}</title></head><body>"
		html << "#{datastore['BODY']}"
		html << "<img src=\"#{reporting_uri}\"></img>"
		html << "</body></html>"

		msg = Rex::MIME::Message.new
		msg.mime_defaults
		msg.subject = datastore['SUBJECT'] || Rex::Text.rand_text_alpha(rand(32)+1)
		msg.to = datastore['MAILTO']
		msg.from = datastore['MAILFROM']
		msg.add_part(Rex::Text.encode_base64(html, "\r\n"), "text/html", "base64", "inline")
		send_message(msg.to_s)
	end


end
