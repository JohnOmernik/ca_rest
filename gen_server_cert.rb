#!/usr/bin/env ruby

# libs
require 'rest-client'
require 'open3'

if ARGV.size < 4
  print "Incorrect usage. Ex: ./gen_server_cert.rb <key password> <path for key, cert and csr to be placed> <CA REST URL> <server name> \n"
  print "\tie: ./gen_server_cert.rb certkeyPass123 /home/crash/certs http://192.168.1.1/csr mesos-web-root \n"
  print "\tService name can be anything, it just identifies what is using this cert.\n"
  abort
end


# consts
KEY_SIZE = 4096
OPENSSL=%x(which openssl).chomp
KEY_PASSWORD = ARGV[0]
URL = ARGV[2]
CERT_FOLDER = ARGV[1]
SERVICE_NAME = ARGV[3]
CERT_BASE = "server_cert_#{Time.now.strftime("%Y-%m-%d")}"
KEY_FILE = CERT_FOLDER + "/" + CERT_BASE + "-key.pem"
CERT_FILE = CERT_FOLDER + "/" + CERT_BASE + "-signed-cert.pem"
CSR_FILE = CERT_FOLDER + "/" + CERT_BASE + ".csr"


# defs
def run_cmd(cmd, message)
  print "Running command: #{cmd} \n"
  stdout, stderr, exit_status = Open3.capture3(cmd)
  if exit_status.exitstatus == 0
    return stdout
  else
    print message
    print "Output: #{stdout} \n"
    print "Error message: #{stderr} \n"
    print "Exit code: #{exit_status} \n"
    abort
  end
end


# test our inputs
unless File.exists?(CERT_FOLDER) && File.readable?(CERT_FOLDER) && File.writable?(CERT_FOLDER)
  print "Certs folder does not exist or is not readable/writable: #{CERT_FOLDER} \n"
  abort
end

unless URL.match(/^http:\/\//)
  print "URL for CA REST path does not resemble a url: #{URL} \n"
  abort
end

unless KEY_PASSWORD.match(/[[:ascii:]]+/)
  print "Key password does not look like a password: #{KEY_PASSWORD} \n"
  abort
end


# generate our key
create_key_cmd = "#{OPENSSL} genrsa -des3 -passout pass:#{KEY_PASSWORD} -out #{KEY_FILE} #{KEY_SIZE}"
print "Generating key.."
not_used = run_cmd(create_key_cmd, "OpenSSL command exited strangely or could not create a key file or it never appeared in the output directory. Aborting. \n")
stdout, stderr, exit_status = Open3.capture3(create_key_cmd)

if File.exists?(KEY_FILE) && File.readable?(KEY_FILE)
  print "Your key file is located at: #{KEY_FILE} \n"
else
  print "Could not create a key file or it never appeared in the output directory. Cert folder: #{CERT_FOLDER} \n"
  abort
end


# generate our CSR
create_csr_cmd = "#{OPENSSL} req -new -passin pass:#{KEY_PASSWORD} -key #{KEY_FILE} -out #{CSR_FILE} -subj \"/C=US/ST=CA/L=Redwood City/O=#{SERVICE_NAME}/CN=#{SERVICE_NAME}\""
print "Generating certificate signature request file..\n"
not_used = run_cmd(create_csr_cmd, "OpenSSL command exited strangely or could not create a CSR file or it never appeared in the output directory. Aborting. \n")


unless File.exists?(CSR_FILE) && File.readable?(CSR_FILE)
  print "OpenSSL command exited strangely or could not create a CSR file or it never appeared in the output directory. Aborting. Directory: #{CERT_FOLDER} \n"
  abort
end

print "Your csr is located at: #{CSR_FILE} \n"

# request and write signed certificate
print "Requesting signed certificate from CA REST interface.. \n"
request = RestClient::Request.new(:method => :post, :url => URL, :payload => { :multipart => true, :file => File.new(CSR_FILE, "rb") })
begin
  response = request.execute
rescue
  print "Something went stupidly wrong with the REST Client response or CA REST server.\n"
  print "Response: #{response.inspect} \n"
  abort
end

unless !response.nil? && response.code == 200 && response.body.match(/-----BEGIN CERTIFICATE-----/)
  print "CA REST API responded strangely or could not return a signed cert. Aborting. \n"
  print "HTTP Code: #{response.code}"
  print "Error: #{response.body} \n"
  abort
end

if response.body.match(/-----BEGIN CERTIFICATE-----/)
  # write it to file
  File.open(CERT_FILE,"w") {|f| f.write(response.body)}
end

print "Your signed cert file is located at: #{CERT_FILE} \n"

# Validate they are both related and the same
print "Validating key and certificate fingerprints match..\n"
key_md5 = run_cmd("#{OPENSSL} rsa -noout -passin pass:#{KEY_PASSWORD} -modulus -in #{KEY_FILE} | #{OPENSSL} md5", "Attempted to validate the key and certificate are matching, but got strange output from openssl. You probably have a valid certificate and key, check this before re-running. \n")
cert_md5 = run_cmd("#{OPENSSL} x509 -noout -modulus -in #{CERT_FILE} | #{OPENSSL} md5", "Attempted to validate the key and certificate are matching, but got strange output from openssl. You probably have a valid certificate and key, check this before re-running. \n" )

if cert_md5 == key_md5
  print "\n\nSuccessfully created key and CA-signed certificate!\n"
  print "Key: \t\t#{KEY_FILE} \n"
  print "Certificate: \t#{CERT_FILE} \n"
  print "Fingerprint: #{cert_md5} \n"
else
  print "Something went wrong..\n"
  print "\tkey md5:\t\t#{key_md5} \n"
  print "\tcert md5:\t#{cert_md5} \n"
  abort
end
