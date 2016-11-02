#!/usr/bin/env ruby

require "sinatra"
require "open3"

if ARGV.size != 3
  print "You must specify a port to listen on,the CA root folder, and a CA Password. ./main.rb 3000 /ca_rest myCAPassword\n"
  abort
end

BIND_PORT = ARGV[0]
CA_ROOT_DIR = ARGV[1]
CA_PASSWORD =  ARGV[2]

unless BIND_PORT.match(/[0-9]+/)
  print "Ports must be numeric: ./main.rb 3000 /rest_ca myCAPassword \n"
  abort
end

unless Dir.exists?(CA_ROOT_DIR) && File.readable?(CA_ROOT_DIR)
  print "CA root directory does not exist or is not readable: #{CA_ROOT_DIR}\n"
  abort
end

unless CA_PASSWORD.size > 0 && CA_PASSWORD.match(/[a-zA-Z0-9]+/)
  print "CA password must be specified: ./main.rb 3000 /rest_ca myCAPassword \n"
  abort
end

enable :logging
set :port, BIND_PORT
set :bind, "0.0.0.0"

get '/cacert' do
  crt_file = "#{CA_ROOT_DIR}/cacert.pem"
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
  openssl_ca_config = "#{CA_ROOT_DIR}/openssl.cnf"
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

  # sign and return cert using 03
  STDERR.puts "Signing csr and generating cert file output, cert: #{crt_tmp_file}"
  openssl_sign_csr_cmd = "#{openssl_cmd} ca -batch -config #{openssl_ca_config} -days 375 -passin pass:#{CA_PASSWORD} -in #{csr_tmp_file} -out #{crt_tmp_file}"
  stdout, stderr, exit_status = Open3.capture3(openssl_sign_csr_cmd)

  #{}"#{stdout} \n #{stderr} \n #{exit_status} \n OK"
  if File.exists?(crt_tmp_file) && File.readable?(crt_tmp_file) && File.size(crt_tmp_file) > 0
    send_file crt_tmp_file, :filename => crt_tmp_file, :type => 'Application/octet-stream'
    File.delete(crt_tmp_file)
    File.delete(csr_tmp_file)
  else
    message = "Something went wrong \n STDOUT: #{stdout} \n STDERR: #{stderr} \n Exit Code: #{exit_status} \n OK"
    STDERR.print message
    status 500
    message
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
