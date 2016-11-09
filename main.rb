#!/usr/bin/env ruby

require "sinatra"
require "open3"

# we check the environment variables first to see if things are necessary.
bind_port = ""
ca_root_dir = ""
ca_password = ""

["SERVER_PORT","CA_ROOT"].each do |var|
  if ENV[var].nil?
    print "Environmental variable not set: #{var} \n\nEnvironmental variables required: \n"
    print "\tSERVER_PORT\tThe port you want the CA REST server to listen on.\n"
    print "\tCA_ROOT\t\tThe directory where your CA is installed.\n"
    abort
  end
end

bind_port = ENV['SERVER_PORT']
ca_root_dir = ENV['CA_ROOT']
ca_password_file = ca_root_dir + "/private/capass.txt"

unless bind_port.match(/[0-9]+/)
  print "Server Port must be numeric. \n"
  abort
end

unless Dir.exists?(ca_root_dir) && File.readable?(ca_root_dir)
  print "CA root directory does not exist or is not readable: #{ca_root_dir}\n"
  abort
end

if File.exists?(ca_password_file) && File.readable?(ca_password_file)
  ca_password = File.read(ca_password_file).chomp
else
  print "CA root password file does not exist or is not readable: #{ca_password_file}\n"
  abort
end

unless ca_password.match(/[[:ascii:]]+/)
  print "CA password does not look like a password: #{ca_password} \n"
  abort
end

print "Bind port set to #{bind_port} \n"
print "CA Root Dir: #{ca_root_dir} \n"

enable :logging
set :port, bind_port
set :bind, "0.0.0.0"

get '/cacert' do
  crt_file = "#{ca_root_dir}/cacert.pem"
  if File.exists?(crt_file) && File.readable?(crt_file) && File.size(crt_file) > 0
    send_file crt_file, :filename => 'cacert.pem', :type => 'Application/octet-stream'
  else
    message = "CA Cert file does not exist or is not readable: #{crt_file}"
    STDERR.print message
    status 500
    message
  end
end

post '/csr' do
  app_root = File.dirname(__FILE__)
  working_directory = app_root + "/tmp"
  id = Time.now.to_i + rand(33000)
  openssl_ca_config = "#{ca_root_dir}/openssl.cnf"
  openssl_cmd = '/usr/bin/openssl'

  unless File.exists?(openssl_ca_config) && File.readable?(openssl_ca_config)
    return "Openssl CA Config does not exist or is not readable: #{openssl_ca_config}"
  end

  unless File.exists?(openssl_cmd) && File.readable?(openssl_cmd)
    return "Openssl command does not exist or is not readable: #{openssl_cmd}"
  end


  # we're expecting a csr file to come with this
  unless params[:file] && (tmpfile = params[:file][:tempfile]) && (name = params[:file][:filename])
    @error = "No file selected for upload."
    return @error
  end

  tmp_file = "#{working_directory}/#{name}_#{id}"
  csr_tmp_file = tmp_file + ".csr"
  crt_tmp_file = tmp_file + ".pem"

  STDERR.puts "Accepted uploaded file and writing to disk, original name #{name}, filename: #{csr_tmp_file}"
  while blk = tmpfile.read(65536)
    File.open(csr_tmp_file, 'wb') {|f| f.write blk }
  end
  STDERR.puts "Upload complete"

  # validate the CSR is for the right CN suffix
  STDERR.puts "Validating CSR is for a *.marathon.mesos CN.."
  verify_csr_cmd = "#{openssl_cmd} req -in #{csr_tmp_file} -noout -text"
  stdout, stderr, exit_status = Open3.capture3(verify_csr_cmd)

  unless stdout.match(/CN=[^\x0d\x0a]+\.marathon(\.slave)?\.mesos/)
    message = "This CA will not sign certificates for any CN that does not end in .marathon.mesos \n"
    STDERR.print message
    status 500
    return "#{message}"
  end

  # sign and return cert using 03
  STDERR.puts "Signing csr and generating cert file output, cert: #{crt_tmp_file}"
  openssl_sign_csr_cmd = "#{openssl_cmd} ca -batch -config #{openssl_ca_config} -days 375 -passin pass:#{ca_password} -in #{csr_tmp_file} -out #{crt_tmp_file}"
  stdout, stderr, exit_status = Open3.capture3(openssl_sign_csr_cmd)

  #{}"#{stdout} \n #{stderr} \n #{exit_status} \n OK"
  if File.exists?(crt_tmp_file) && File.readable?(crt_tmp_file) && File.size(crt_tmp_file) > 0
    status 200
    send_file crt_tmp_file, :filename => crt_tmp_file, :type => 'Application/octet-stream'
    File.delete(crt_tmp_file) if File.exists?(crt_tmp_file)
    File.delete(csr_tmp_file) if File.exists?(csr_tmp_file)
  else
    message = "Something went wrong \n STDOUT: #{stdout} \n STDERR: #{stderr} \n Exit Code: #{exit_status} \n OK"
    STDERR.print message
    status 500
    return "#{message}"
  end
end

# NYI
get '/certs/:fingerprint' do
  # get all cert fingerprints
  # for x in $(ls /etc/ssl/CA/newcerts/*.pem); do /usr/bin/openssl x509 -noout -modulus -in $x | openssl md5 | awk '{print $2}'; done
end

get '*' do
  status 404
  "These are not the certs you're looking for."
end
