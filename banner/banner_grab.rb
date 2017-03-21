##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'


class MetasploitModule < Msf::Auxiliary
  
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'General Server Banner Grabber',
      'Description' => %q{
        This module grabs the banner of any webserver
        as long as the port is open.
      },
      'Author'      => 'thecarterb',
      'License'     => MSF_LICENSE
    )
  end

  def run_host(ip)
    res = connect
    #banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
    print_status("#{print_prefix}")
    report_service(:host => rhost, :port => rport, :info => print_prefix)
  end
end
