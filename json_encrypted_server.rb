# JSON small server to test json_crypto_helper Burp extension
# Copyright : Christophe De La Fuente - at gmail: chrisdlf.dev

require "openssl"
require 'webrick'
require 'json'

module EncryptionHelper
  # Encryption information: adapt it according to your needs
  KEY = "\xa0\xcc\x91\x18\x53\x41\xd6\xa2\x7c\x38\x0e\x97\xfe\xd3\x0b\x4a\x1d\xca\xfd\x7f\x50\x44\xf0\x9c\xc7\xfa\x6b\x3f\xa0\xdf\x29\x0b"
  IV = "\xab\xda\xd4\xa9\x4d\x54\x4b\x52\xf4\x78\x2e\x28\x56\xf8\x28\x74"
  ALGO = "aes-128-cbc"

  def encrypt text
      cipher = OpenSSL::Cipher::Cipher.new(ALGO)
      cipher.encrypt
      cipher.key = KEY
      cipher.iv = IV
      ciphertext = cipher.update(text)
      ciphertext << cipher.final
  end

  def decrypt ciphertext
      cipher = OpenSSL::Cipher::Cipher.new(ALGO)
      cipher.decrypt
      cipher.key = KEY
      cipher.iv = IV
      text = cipher.update(ciphertext)
      text << cipher.final
  end

  def encode_b64 text
      [text].pack('m0')
  end

  def decode_b64 encoded_text
      encoded_text.unpack('m')[0]
  end

  def decrypt_json(json)
    json.each do |key, value|
      if value.is_a?(Hash)
        json[key] = decrypt_json(value)
      else
        value_tmp = decode_b64(value)
        if value_tmp.empty?
          json[key] = value
        else
          json[key] = decrypt(value_tmp)
        end
      end
    end
    json
  end

  def encrypt_json(json)
    json.each do |key, value|
      if value.is_a?(Hash)
        json[key] = encrypt_json(value)
      else
        if value.empty?
          json[key] = value
        else
          json[key] = encode_b64(encrypt(value))
        end
      end
    end
    json
  end
end

class EncodedInfo < WEBrick::HTTPServlet::AbstractServlet
  include EncryptionHelper

  def do_GET request, response
    response.status = 200
    response['Content-Type'] = 'application/json; charset=utf-8'

    my_hash = {
      :hello => encode_b64(encrypt("world!")),
      :test => {
        :input1 => encode_b64(encrypt("hey")),
        :input2 => encode_b64(encrypt("can you read that?"))
      }
    }
    json = JSON.generate(my_hash)
    response.body = json
  end

  def do_POST request, response
    response.status = 200
    response['Content-Type'] = 'application/json; charset=utf-8'

    message = ""
    begin
      json = JSON.parse(request.body)
      json = decrypt_json(json)
      message << JSON.pretty_generate(json)
    rescue OpenSSL::Cipher::CipherError => e
      puts "Cryptogrphy error: #{e.message}"
      message << "Cryptogrphy Error."
    rescue JSON::ParserError => e
      puts "Parsing error: #{e.message}"
      message << "JSON Parsing Error. Is it a proper JSON?"
    end
    response.body = message
  end
end

## main ##
server = WEBrick::HTTPServer.new(:Port => 8888)
server.mount('/', EncodedInfo)
trap 'INT' do server.shutdown end
server.start

