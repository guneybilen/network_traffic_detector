require 'packetgen'
require 'resolv'
require 'socket'
require 'webrick'
require 'json'
require 'base64'
require 'open3'
require_relative "block_an_ip"

def html_output(txt_output, txt_color, ip_src = nil)
  if ip_src
    output = <<-HTML
    <p style='color: #{txt_color}'>#{txt_output}</p>
    <li>You want to block this IP? Just click on it <a href="#" ondblclick="sendIp('#{ip_src}')">#{ip_src}</a></li>
    <script>
      function sendIp(ip) {
        fetch('/handle_ip', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ ip: ip })
        })
        .then(response => response.text())
        .then(data => {
          console.log('Response from server:', data);
        })
        .catch(error => {
          console.error('Error:', error);
        });
      }
    </script>
HTML
  else
      output = <<-HTML
      <p style='color: #{txt_color}'>#{txt_output}</p>
HTML
  end
    
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
      return nil
    end
  end
end

# Specify the network interface
iface = 'en8'

# Store outgoing destinations
outgoing_destinations = {}

# Router address
router_address = '192.168.1.1'

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


# Mapping of protocol numbers to protocol names
protocol_names = {
  1 => 'ICMP',
  2 => 'IGMP',
  6 => 'TCP',
  17 => 'UDP',
  41 => 'IPv6',
  50 => 'ESP',
  51 => 'AH',
  58 => 'ICMPv6',
  89 => 'OSPF'
}


# Function to convert flag value to a hash
def get_tcp_flags_hash(flags, tcp_flags)
  tcp_flags.each_with_object({}) do |(flag, name), hash|
    hash[name] = (flags & flag != 0)
  end
end

def protocol_number(pkt)
  return pkt.ip.protocol
end

def binary_data?(data)
  return data.bytes.any? { |byte| byte < 32 || byte > 126 }
end

def pkt_flags(pkt)

  # Mapping of TCP flag values to their corresponding names
  tcp_flags = {
    0x01 => 'FIN',
    0x02 => 'SYN',
    0x04 => 'RST',
    0x08 => 'PSH',
    0x10 => 'ACK',
    0x20 => 'URG',
    0x40 => 'ECE',
    0x80 => 'CWR'
  }

  # Get the TCP flags from the packet
  tcp_flag_value = pkt.tcp.flags

  # Convert the TCP flags to a hash
  tcp_flags_hash = get_tcp_flags_hash(tcp_flag_value, tcp_flags)

  split_point = tcp_flags_hash.keys.length
   
  # Define the split points
  split1 = split_point / 2
  split2 = split_point

  # Create two new hashes based on the split keys
  tcp_flags_part1 = tcp_flags_hash.select.with_index { |(_, _), i| i < split1 }
  tcp_flags_part2 = tcp_flags_hash.select.with_index { |(_, _), i| i >= split1 && i < split2 }
 
  # Convert each part to pretty-printed JSON
  pretty_json_part1 = JSON.pretty_generate(tcp_flags_part1)
  pretty_json_part2 = JSON.pretty_generate(tcp_flags_part2)

  html_output pretty_json_part1, :brown
  html_output pretty_json_part2, :brown

end



def print_organization_name_for_unreselved_ip(ip_address)
  # Run the whois command and capture the output
  stdout, stderr, status = Open3.capture3("whois #{ip_address}")

  if status.success?
    organization = stdout.match(/OrgName:\s*(.*)/)
    country = stdout.match(/Country:\s*(.*)/)
    if organization
      html_output "Organization: #{organization[1]}", :black
    else
      html_output "Organization information not found.", :black
    end
    if country
      html_output "Country: #{country[1]}", :black
    else
      html_output "Country information not found.", :black
    end
  else
    html_output "Error: #{stderr}", :red
  end
  html_output "====================", :grey
end

def print_body(body)
# Access and print the payload content
  if body == ""
    html_output "Payload is Empty", :green
  else  
    if binary_data?(body)
      encoded_payload = Base64.encode64(body)
      html_output "Payload: #{encoded_payload}", :green
    else
      html_output "Payload: #{body}", :green
    end
  end
end


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
              
              protocol = protocol_number(pkt)
              
              # Get the protocol name from the mapping
              protocol_name = protocol_names[protocol] || "Unknown Protocol (#{protocol})"
           
              # Generate a packet and convert it to binary
              binary_packet = pkt.to_s
              # Access and print the source and destination ports
              
              html_output "Source Port: #{pkt.tcp.sport}, Destination Port: #{pkt.tcp.dport}", :blue 
              
              # Print the size of the packet
              html_output "Packet Size: #{binary_packet.size} bytes", :orange
             
              print_body(pkt.tcp.body)
            
              pkt_flags(pkt)

              html_output("#{protocol_name} : Unknown incoming traffic from: #{ip_src} addressed to #{ip_dst}", :red, ip_src)

              print_organization_name_for_unreselved_ip(ip_src)
          
              #html_output("Incoming traffic from: #{hostname} (#{ip_src})", :blue)

              #puts pkt.inspect
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

class IPHandler < WEBrick::HTTPServlet::AbstractServlet
  def do_POST(req, res)
    data = JSON.parse(req.body)
    ip_address = data['ip']

    # Process the IP address as needed
    # For example, log the IP address or block it using the previous pf method

    puts "Received IP: #{ip_address}"
    block_ip(ip_address)
    
    res.status = 200
    res['Content-Type'] = 'application/json'
    res.body = { status: 'success', received_ip: ip_address }.to_json
  end
end

server = WEBrick::HTTPServer.new(Port: 8000, DocumentRoot: Dir.pwd)

# Serve the HTML file
server.mount_proc '/' do |req, res|
  res.content_type = 'text/html'
  res.body = File.read('content.html')
end

# Mount the IPHandler servlet to handle POST requests
server.mount '/handle_ip', IPHandler

# Signal handler to clear content.html on Ctrl+C
Signal.trap("INT") do
  File.open('content.html', 'w') { |file| file.truncate(0) }
  puts "\nCleared content.html"
  server.shutdown
  exit
end
  
puts 'Starting server on http://localhost:8000'
server.start
