require 'webrick'

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

# Create and start the WEBrick server
server = WEBrick::HTTPServer.new(
  Port: 8000,
  DocumentRoot: Dir.pwd
)

# Mount the root directory with the custom CORS handler
server.mount('/', CORSHandler, Dir.pwd)

trap('INT') { server.shutdown }
puts 'Starting server on http://localhost:8000'
server.start
