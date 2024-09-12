require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Hello World',
      'Description'    => %q{
        This module simply prints "Hello".
      },
      'Author'         => [ 'WeiHeng' ],
      'License'        => MSF_LICENSE
    ))
  end

  def run
    print_line("Hello")
  end
end
