require 'open3'

# Function to update the custom pf configuration file
def update_pf_config(rule)
  custom_pf_path = '/etc/pf.custom.conf'
  
  # Add the new rule to the custom pf configuration file
  File.open(custom_pf_path, 'a') do |file|
    file.puts(rule)
  end
  
  # Reload the pf configuration to apply the changes
  reload_pf_config
end

# Function to reload the pf configuration
def reload_pf_config
  default_pf_path = '/etc/pf.conf'
  custom_include_statement = 'include "/etc/pf.custom.conf"'

  # Check if the custom include statement is already present in the default pf.conf
  unless File.readlines(default_pf_path).grep(/#{Regexp.escape(custom_include_statement)}/).any?
    # If not present, add the include statement to the default pf.conf
    File.open(default_pf_path, 'a') do |file|
      file.puts(custom_include_statement)
    end
  end

  # Load the default pf configuration which includes the custom file
  stdout, stderr, status = Open3.capture3("sudo pfctl -f #{default_pf_path}")

  if status.success?
    # Enable pf if it's not already enabled
    Open3.capture3("sudo pfctl -e")
    puts "pf configuration reloaded successfully."
  else
    puts "Error reloading pf configuration: #{stderr}"
  end
end

def block_ip(ip)
  rule_to_block = "block drop in from #{ip} to any"
  update_pf_config(rule_to_block)
end
