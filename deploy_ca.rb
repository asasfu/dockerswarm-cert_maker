#!/usr/bin/env ruby

require 'json'
require 'yaml'
require 'socket'
require 'open3'
require 'optparse'

class String
  def to_bool
    return true if self == true || self =~ (/^(true|t|yes|y|1)$/i)
    return false if self == false || self.empty? || self =~ (/^(false|f|no|n|0)$/i)
    raise ArgumentError.new("invalid value for Boolean: \"#{self}\"")
  end
end

class Fixnum
  def to_bool
    return true if self == 1
    return false if self == 0
    raise ArgumentError.new("invalid value for Boolean: \"#{self}\"")
  end
end

class TrueClass
  def to_i; 1; end
  def to_bool; self; end
end

class FalseClass
  def to_i; 0; end
  def to_bool; self; end
end

class NilClass
  def to_bool; false; end
end

class Certificate_common
  def initialize(basedir)
    @basedir = basedir
  end
  def std_cmd(cmd)
    Open3.popen2e(cmd, :chdir=>@basedir) do |stdin, stdout_err, thread|
      stdin.close
      stdout_err.each_line do |line|
        puts line
      end
    end
  end
  def openssl_run(cmd, stdin_commands=[])
    process_result = 2
    Open3.popen2e("openssl #{cmd}", :chdir=>@basedir) do |stdin, stdout_err, thread|
      stdin_commands.each do |in_cmd|
        stdin.puts(in_cmd)
      end
      stdin.close
      stdout_err.each_line do |line|
        puts line
        if line.include?('error')
          puts "Ran into error during openssl_run, see message output in line above and attempt to fix"
        end
      end
      process_result = thread.value.success?
    end
    return process_result
  end
  def set_file_mode(mode, *filenames)
    filenames.each do |filename|
      full_filepath = File.path(filename).include?(@basedir) ? filename : "#{@basedir}/#{filename}"
      warn("Filename: #{full_filepath} was not found, unable to chmod #{mode} #{full_filepath}") unless File.exist?(full_filepath)
      File.chmod(mode, full_filepath)
    end
  end
end
class CA_Certificate < Certificate_common
  attr_reader :node_name, :bitrate, :encryption, :hash, :days, :filename
  def initialize(args={})
    options = defaults.merge(args)

    super(options.fetch(:basedir))
    @node_name  = options.fetch(:node_name)
    @pas_wrd    = options.fetch(:pas_wrd)
    @bitrate    = options.fetch(:bitrate)
    @encryption = options.fetch(:encryption)
    @hash       = options.fetch(:hash)
    @days       = options.fetch(:days)
    @filename   = options.fetch(:filename)
  end
  def defaults
    {
      :bitrate    => '4096',
      :encryption => 'aes256',
      :hash       => 'sha256',
      :days       => '1056',
      :filename   => '/tmp/pd.tmp'
    }
  end
  def prepare_pas_wrd
    File.open(@filename, 'w') { |fo| fo.puts @pas_wrd }
  end
  def destroy_pas_wrd
    File.delete(@filename)
  end
  def create_key
    result = openssl_run("genrsa -passout file:#{@filename} -#{@encryption} -out ca-key.pem #{@bitrate}")
    set_file_mode(0400, "#{@basedir}/ca-key.pem")
    fail("Failed while creating CA key for #{@node_name}") unless result
  end
  def create_pem(ca_hash={})
    ca_hash[:cn] ||= @node_name
    result = openssl_run(
      "req -passin file:#{@filename} -new -x509 -days #{@days} -key ca-key.pem -#{@hash} -out ca.pem",
      [
        ca_hash[:country],
        ca_hash[:prov_state],
        ca_hash[:city],
        ca_hash[:org],
        ca_hash[:org_unit],
        ca_hash[:cn],
        ca_hash[:email]
      ]
    )
    set_file_mode(0444, "#{@basedir}/ca.pem")
    fail("Failed while creating CA pem for #{@node_name}") unless result
  end
end
class Certificate < Certificate_common
  attr_reader :node_name, :bitrate, :hash, :days, :filename
  def initialize(args={})
    options = defaults.merge(args)

    super(options.fetch(:basedir))
    @node_name  = options.fetch(:node_name)
    @bitrate    = options.fetch(:bitrate)
    @hash       = options.fetch(:hash)
    @days       = options.fetch(:days)
    @filename   = options.fetch(:filename)
    @client     = options.fetch(:client)
    @ipaddress  = options.fetch(:ipaddress)
  end
  def defaults
    {
      :bitrate    => '4096',
      :hash       => 'sha256',
      :days       => '1056',
      :filename   => '/tmp/pd.tmp',
      :client     => true,
      :ipaddress  => nil
    }
  end
  def create_key
    key_name = @client == true ? "#{@node_name}-key.pem" : "#{@node_name}-server-key.pem"
    result = openssl_run("genrsa #{"-passout file:#{@filename}" if not @client == true} -out #{key_name} #{@bitrate}")
    set_file_mode(0400, "#{@basedir}/#{key_name}")
    fail("Failed while creating #{"server-" if not @client == true}key for #{@node_name}") unless result
  end
  def create_csr
    result = openssl_run("req #{"-passin file:#{@filename}" if not @client == true} -subj \"/CN=#{@node_name}\" -#{@hash} -new -key #{@node_name}#{"-server" if not @client == true}-key.pem -out #{@node_name}.csr")
    fail("Failed while creating #{"server-" if not @client == true}csr for #{@node_name}") unless result
  end
  def create_pem
    cert_name = @client == true ? "#{@node_name}.pem" : "#{@node_name}-server.pem"
    result = openssl_run("x509 -passin file:#{@filename} -req -days #{@days} -#{@hash} -in #{@node_name}.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out #{cert_name} -extfile extfile.cnf")
    File.delete("#{@basedir}/#{@node_name}.csr")
    File.delete("#{@basedir}/extfile.cnf")
    set_file_mode(0444, "#{@basedir}/#{cert_name}")
    fail("Failed while creating #{"server-" if not @client == true}pem for #{@node_name}") unless result
  end
  def extfile
    fail("You specified that this is a server node(The CA server) and you did not specify the ipaddress for it to put in the SAN of the cert") if (!@client == true) && (@ipaddress.nil?)
    line = @client == true ? "echo extendedKeyUsage = clientAuth,serverAuth > extfile.cnf" : "echo subjectAltName = IP:#{@ipaddress} > extfile.cnf"
    std_cmd(line)
  end
end
def deep_symbolize(element)
  return element.collect { |e| deep_symbolize(e) } if element.is_a?(Array)
  return element.inject({}) { |sh,(k,v)| sh[k.to_sym] = deep_symbolize(v); sh } if element.is_a?(Hash)
  element
end

options = { 
  :basedir     => nil,
  :server_name => Socket.gethostbyname(Socket.gethostname)[0],
  :node_name   => nil,
  :pas_wrd     => nil,
  :days        => '1056',
  :ca          => false,
  :yaml        => nil
}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: deploy_ca.rb [options]"
  opts.on('-b', '--basedir basedir', 'Basedir for cert output') do |basedir|
    options[:basedir] = basedir
  end 
  opts.on('-n', '--nodename hostname', 'Hostname of the machine to receive a client auth certificate') do |node_name|
    options[:node_name] = node_name
  end 
  opts.on('-s', '--servername server_hostname', 'Server name (the name of the CA Server, also should be the name of the server you\'re running this on)') do |server_name|
    options[:server_name] = server_name
  end 
  opts.on('-p', '--password password', 'Password for keys') do |pas_wrd|
    options[:pas_wrd] = pas_wrd
  end 
  opts.on('-d', '--days days_to_sign_for', 'Length of days to certify for') do |days|
    options[:days] = days
  end 
  opts.on('-c', '--ca true|false', 'Whether or not we\'ll be setting up the CA during this run as well as node or just adding a node cert') do |ca|
    options[:ca] = ca.to_bool
  end 
  opts.on('-y', '--yaml yaml_file', 'YAML that contains all the settings required') do |yaml|
    options[:yaml] = yaml
  end 
  opts.on('-j', '--json json_file', 'JSON that contains all the settings required') do |json|
    options[:json] = json
  end 
  opts.on('-h', '--help', 'Displays Help') do
    puts opts
    exit
  end
end
parser.parse!
if options[:yaml].nil? && options[:json].nil?
  if options[:basedir] == nil
    print 'Enter Basedir: '
    options[:basedir] = gets.chomp
  end
  if options[:node_name] == nil
    print 'Enter Hostname: '
    options[:node_name] = gets.chomp
  end
  if options[:pas_wrd] == nil
    print 'Enter Password: '
    options[:pas_wrd] = gets.chomp
  end
  if options[:days] == nil
    print 'Enter Days: '
    options[:days] = gets.chomp
  end
else
  my_yaml = deep_symbolize(YAML.load_file(options[:yaml])) if options[:yaml]
  my_yaml = deep_symbolize(JSON.parse(File.read(options[:json]))) if options[:json]
  options.merge!(my_yaml) unless my_yaml.empty?
  file_path = options[:yaml].nil? ? options[:json] : options[:yaml]
  options[:basedir] = File.dirname(File.absolute_path(file_path, Dir.pwd)) if options[:basedir] == '.' or options[:basedir].nil?
end
fail("Missing file directory #{options[:basedir]}") unless File.exist?(options[:basedir])
fail("You must use a YAML or JSON file for input if --ca true as it needs more detail (:ca_details)") if options[:ca] == true && ((options[:yaml].nil? || options[:yaml].empty?) && (options[:json].nil? || options[:json].empty?))
options[:node_name] = options[:node_name].split(' ') if options[:node_name].is_a?(String)
my_ca = CA_Certificate.new(
  :basedir     => options[:basedir],
  :node_name   => options[:server_name],
  :pas_wrd     => options[:pas_wrd],
)
my_ca.prepare_pas_wrd
if options[:ca] == true
  fail("Missing CA details") if options[:ca_details].nil? or options[:ca_details].empty?
  ipaddress = Socket.getaddrinfo(options[:server_name], nil, Socket::AF_UNSPEC, Socket::SOCK_STREAM, nil, Socket::AI_CANONNAME, false)[0][3]
  my_ca.create_key
  my_ca.create_pem(options[:ca_details])
  my_server = Certificate.new(
    :basedir   => options[:basedir],
    :node_name => options[:server_name],
    :ipaddress => ipaddress,
    :days      => options[:days],
    :client    => false
  )
  my_server.create_key
  my_server.create_csr
  my_server.extfile
  my_server.create_pem
end
options[:node_name].each do |node|
  my_node = Certificate.new(
    :basedir   => options[:basedir],
    :node_name => node,
    :days      => options[:days],
    :client    => true
  )
  my_node.create_key
  my_node.create_csr
  my_node.extfile
  my_node.create_pem
end
my_ca.destroy_pas_wrd
