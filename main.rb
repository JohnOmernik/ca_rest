#!/usr/bin/env ruby
# CA_REST
# A REST API in-a-box for Certificate Authorities in development environments.
# Ryan C. Moon (@ryancmoon)
# 2016-11-09
# Apache License v2.0 -- http://www.apache.org/licenses/

require "sinatra"
require "open3"

# we check the environment variables first to see if things are necessary.
bind_port = ""

["SERVER_PORT","CA_ROOT","JAVA_HOME"].each do |var|
  if ENV[var].nil?
    print "Environmental variable not set: #{var} \n\nEnvironmental variables required: \n"
    print "\tSERVER_PORT\tThe port you want the CA REST server to listen on.\n"
    print "\tCA_ROOT\t\tThe directory where your CA is installed.\n"
    abort
  end
end

bind_port = ENV['SERVER_PORT']
java_home = ENV['JAVA_HOME']
ca_root = ENV['CA_ROOT']
keytool_bin = java_home + "/bin/keytool"
app_root = File.dirname(__FILE__)

# quick check to make sure this exists
unless Dir.exists?(ca_root) && File.readable?(ca_root)
  print "CA root directory does not exist or is not readable: #{ca_root}\n"
  abort
end

options = {
  'ca_root_dir' => ca_root,
  'ca_password_file' => ca_root + "/private/capass.txt",
  'ca_certs_dir' => ca_root + '/newcerts',
  'ca_password' => '',
  'working_directory' => app_root + "/tmp",
  'id' => Time.now.to_i + rand(33000),
  'openssl_ca_config' => ca_root + "/openssl.cnf",
  'openssl_cmd' => '/usr/bin/openssl',
  'CN' => '',
  'valid_cn_suffix' => Regexp.new(/CN=(:?[^\x0d\x0a]+\.)?marathon(:?\.slave)?\.mesos/)
}

# continue validating.
unless File.exists?(options['openssl_ca_config']) && File.readable?(options['openssl_ca_config'])
  print "Openssl CA Config does not exist or is not readable: #{options['openssl_ca_config']}\n"
  abort
end

unless File.exists?(options['openssl_cmd']) && File.readable?(options['openssl_cmd'])
  print "Openssl command does not exist or is not readable: #{options['openssl_cmd']} \n"
  abort
end

unless bind_port.match(/[0-9]+/)
  print "Server Port must be numeric. \n"
  abort
end

unless File.exists?(options['ca_certs_dir']) && File.readable?(options['ca_certs_dir'])
  print "CA Certs directory does not exist or is not readable: #{options['ca_certs_dir']} \n"
  abort
end


if File.exists?(options['ca_password_file']) && File.readable?(options['ca_password_file'])
  options['ca_password'] = File.read(options['ca_password_file']).chomp
else
  print "CA root password file does not exist or is not readable: #{options['ca_password_file']}\n"
  abort
end

unless options['ca_password'].match(/[[:ascii:]]+/)
  print "CA password does not look like a password: #{options['ca_password']} \n"
  abort
end

unless File.exists?(java_home) && File.readable?(java_home)
  print "JAVA_HOME is defined, but does not exist or is not readable: #{java_home}\n"
  abort
end

unless File.exists?(keytool_bin) && File.readable?(keytool_bin)
  print "Keytool is missing or not readable: #{keytool_bin}\n"
  abort
end

# check it tmp folder exists, if not, create it.
Dir.mkdir(File.dirname(__FILE__) + "/tmp", 0700) unless Dir.exists?(File.dirname(__FILE__) + "/tmp")

#### defs #######
def generate_cert_from_csr(options)
  http_status = 200
  message = ""

  # we're expecting a csr file to come with this
  unless params[:file] && (tmpfile = params[:file][:tempfile]) && (name = params[:file][:filename])
    return [500,"No file selected for upload."]
  end

  tmp_file = "#{options['working_directory']}/#{name}_#{options['id']}"
  csr_tmp_file = tmp_file + ".csr"
  crt_tmp_file = tmp_file + ".pem"

  STDERR.puts "Accepted uploaded file and writing to disk, original name #{name}, filename: #{csr_tmp_file}"
  while blk = tmpfile.read(65536)
    File.open(csr_tmp_file, 'wb') {|f| f.write blk }
  end
  STDERR.puts "Upload complete"

  # validate the CSR is for the right CN suffix
  unless validate_cn(options,csr_tmp_file)
    message = "This CA will not sign certificates for any CN that does not end in #{options['valid_cn_suffix']} \n"
    STDERR.print message
  end


  # capture our CN
  options['CN'] = return_cn(options,csr_tmp_file)

  # sign and return cert using 03
  STDERR.puts "Signing csr and generating cert file output, cert: #{crt_tmp_file}"
  openssl_sign_csr_cmd = "#{options['openssl_cmd']} ca -batch -config #{options['openssl_ca_config']} -days 375 -passin pass:#{options['ca_password']} -in #{csr_tmp_file} -out #{crt_tmp_file}"
  stdout, stderr, exit_status = Open3.capture3(openssl_sign_csr_cmd)

  #{}"#{stdout} \n #{stderr} \n #{exit_status} \n OK"
  if File.exists?(crt_tmp_file) && File.readable?(crt_tmp_file) && File.size(crt_tmp_file) > 0
    http_status = 200
    message = File.read(crt_tmp_file)
    File.delete(crt_tmp_file) if File.exists?(crt_tmp_file)
    File.delete(csr_tmp_file) if File.exists?(csr_tmp_file)
  else
    message = "Something went wrong \n STDOUT: #{stdout} \n STDERR: #{stderr} \n Exit Code: #{exit_status} \n"
    STDERR.print message
    http_status = 500
  end

  return [http_status, message]
end

# validates the CSR's CN field is a valid name we want to sign for
def validate_cn(options,cert_file)
  STDERR.puts "Validating CSR is for a *.marathon.mesos CN.."
  cn = return_cn(options,cert_file)

  (cn.match(options['valid_cn_suffix'])) ? true : false
end

# returns the CSR's CN= field
def return_cn(options,cert_file)
  STDERR.puts "Grabbing cert CN.."
  verify_csr_cmd = "#{options['openssl_cmd']} req -in #{cert_file} -noout -text"
  stdout, stderr, exit_status = Open3.capture3(verify_csr_cmd)

  # capture our CN
  match = stdout.match(/CN=[^\n]+/)
  if match.nil? || match.size < 4
    return ""
  else
    return match.to_s[3..-1]
  end
end

def get_cert_fingerprint_md5(options,cert_file)
  return nil unless File.exists?(cert_file) && File.readable?(cert_file)

  fp_cmd = "#{options['openssl_cmd']} x509 -noout -modulus -in #{cert_file} | openssl md5"
  stdout, stderr, exit_status = Open3.capture3(fp_cmd)

  return nil unless stdout.match(/^\(stdin\)=/)
  md5 = stdout.match(/[a-f0-9]{32}/).to_s

  return md5 if md5.size == 32
  return nil
end

def get_fingerprints_of_current_certs(options)
  STDERR.print "Gathering all cert fingerprints in our database..\n"
  fingerprints = {}
  Dir.entries(options['ca_certs_dir']).each do |entry|
    file = options['ca_certs_dir'] + "/" + entry
    next if file == "." || file == ".." || !file.match(/.pem$/)

    fp = get_cert_fingerprint_md5(options,file)

    unless fp.nil?
      fingerprints[fp] = "1"
      STDERR.print "Found cert fingerprint in database: #{fp} \n"
    end
  end

  return fingerprints
end

#### Main #######

print "Bind port set to #{bind_port} \n"
print "CA Root Dir: #{options['ca_root_dir']} \n"

enable :logging
set :port, bind_port
set :bind, "0.0.0.0"

# generate our fingerprints file


get '/cacert' do
  crt_file = "#{options['ca_root_dir']}/cacert.pem"
  if File.exists?(crt_file) && File.readable?(crt_file) && File.size(crt_file) > 0
    send_file crt_file, :filename => "cacert.pem", :type => 'Application/octet-stream'
  else
    message = "CA Cert file does not exist or is not readable: #{crt_file}"
    STDERR.print message
    status 500
    message
  end
end

post '/csr' do
  http_status, cert_message = generate_cert_from_csr(options)

  if http_status == 200 && cert_message.match(/-----BEGIN CERTIFICATE-----/)
    status 200
    content_type 'application/octet-stream'
    cert_message
  else
    status 500
    cert_message
  end
end


# returns 200/OK if the fingerprint is in our database
get '/certs/:fingerprint' do
  fingerprint = params['fingerprint']
  unless fingerprint.match(/\A[a-f0-9]{32}\z/)
    status 500
    return "This is not a valid fingerprint: #{fingerprint}"
  end

  fingerprints = get_fingerprints_of_current_certs(options)

  if fingerprints[fingerprint] == "1"
    status 200
    "OK"
  else
    status 404
    "Not found"
  end
end

get '*' do
  status 404
  "These are not the certs you're looking for."
end
