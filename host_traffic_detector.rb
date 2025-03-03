require 'packetgen'
require 'resolv'
require 'socket'
require 'webrick'


def html_output(txt_output, txt_color)
    output = <<-HTML
    <p style='color: #{txt_color}'>#{txt_output}</p>
HTML
    
    # Append the HTML content to a file
    File.open('content.html', 'a') { |file| file.write(output) }
end

def get_ip_address
  # Iterate through all network interfaces
  Socket.ip_address_list.each do |addr_info|
    # Skip loopback addresses
    next if addr_info.ipv4_loopback? || addr_info.ipv6_loopback?

    # Return the non-loopback IPv4 address
    return addr_info.ip_address if addr_info.ipv4?
  end
end

# Define a custom warning handler
module WarningCapture
  def self.write(message)
    # Capture and log the warning message
    # puts "Captured Warning: #{message}"
  end

  def self.flush; end

  def self.<<(message)
    self.write(message)
  end
end

# Redirect warnings to the custom handler
original_stderr = $stderr
$stderr = WarningCapture

def resolve_hostname(ip_address)
  case ip_address
  when "8.8.8.8", "8.8.4.4"
    "Google DNS"
  when "192.168.1.1"
    "router address"
  when get_ip_address
    "Host running the code"
  else
    begin
      Resolv.getname(ip_address)
    rescue StandardError => e
      html_output("Error in resolve_hostname #{e}", :red)
      "No Hostname"
    end
  end
end

# Specify the network interface
iface = 'en8'

# Store outgoing destinations
outgoing_destinations = {}

# Router address
router_address = '192.168.1.1'

# Start the WEBrick server
server = WEBrick::HTTPServer.new(
  Port: 8000,
  DocumentRoot: Dir.pwd,
)

# Define a custom HTTP servlet with CORS support
class CORSHandler < WEBrick::HTTPServlet::FileHandler
  def do_GET(request, response)
    super
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'Content-Type'
  end

  def do_OPTIONS(request, response)
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'Content-Type'
    response.status = 200
  end
end

# Mount the root directory with the custom CORS handler
server.mount('/', CORSHandler, Dir.pwd)

# Run the packet capturing in a separate thread
Thread.new do
  # Capture packets on the specified network interface
  begin
    PacketGen.capture(iface: iface, promisc: true) do |pkt|
      if pkt.is?('IP')
        ip_src = pkt.ip.src.to_s
        ip_dst = pkt.ip.dst.to_s

        # Check if the packet is a TCP packet and has SYN flag set (indicates a connection initiation)
        if pkt.is?('TCP') && pkt.tcp.flag_syn?
          # Log outgoing traffic
          hostname = resolve_hostname(ip_dst)
          outgoing_destinations[ip_dst] = hostname
          # html_output("Outgoing traffic to: #{hostname} (#{ip_dst})", :blue)
        end

        # Check incoming traffic
        if pkt.is?('TCP') && pkt.tcp.flag_ack?
          # Check if the incoming traffic originates from known outgoing destinations
          if outgoing_destinations.key?(ip_src)
            hostname = resolve_hostname(ip_src)
            #html_output("Incoming traffic from: #{hostname} (#{ip_src})", :green)
          elsif ip_src == '192.168.1.23'
            #html_output("Incoming traffic from host address: #{ip_src}", :green)
          elsif ip_src == router_address
            #html_output("Incoming traffic from router address: #{ip_src}", :green)
          else
            if hostname.nil?
              hostname = resolve_hostname(ip_src)
              html_output("Unknown incoming traffic from: #{ip_src}", :red)
            else
              #html_output("Incoming traffic from: #{hostname} (#{ip_src})", :blue)
            end
          end
        end
      end
    end
  rescue StandardError => e
    html_output("An error occurred: #{e.message}", :red)
    # Get the line number of the error
    line_number = e.backtrace.first.split(":")[1]
    html_output("Error occurred on line number: #{line_number}", :red)
  ensure
    # Restore original $stderr
    $stderr = original_stderr
  end
end

# Signal handler to clear content.html on Ctrl+C
Signal.trap("INT") do
  File.open('content.html', 'w') { |file| file.truncate(0) }
  puts "\nCleared content.html"
  server.shutdown
  exit
end
  
puts 'Starting server on http://localhost:8000'
server.start