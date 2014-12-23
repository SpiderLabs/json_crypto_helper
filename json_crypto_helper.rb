# JSON Crypto Helper - Burp Extension
# Copyright : Christophe De La Fuente - at gmail: chrisdlf.dev
#
# Command line example:
# JRUBY_HOME=$MY_RUBY_HOME java -XX:MaxPermSize=1G -Djsse.enableSNIExtension=false -Xmx1g -Xms1g -jar ./burpsuite

require 'java'
require "openssl"
require "json"

java_import 'burp.IBurpExtender'
java_import 'burp.IMessageEditorTabFactory'
java_import 'burp.IMessageEditorTab'
java_import 'burp.IRequestInfo'
java_import 'burp.IIntruderPayloadProcessor'

DISPLAY_NAME= "JSON Crypto Helper"

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

class JSONDecryptorTab
  include IMessageEditorTab
  include EncryptionHelper

  def initialize(callbacks, editable)
    @stderr = callbacks.get_stderr()
    @helper = callbacks.get_helpers()
    @txt_input = callbacks.create_text_editor()
    @editable = editable
  end

  def process_json(json, mode = :no_encryption)
    message = ""
    begin
      json_tmp = JSON.parse(json)
      if mode == :decrypt
        json_tmp = decrypt_json(json_tmp)
      elsif mode == :encrypt
        json_tmp = encrypt_json(json_tmp)
      end
      message << JSON.pretty_generate(json_tmp)
    rescue OpenSSL::Cipher::CipherError => e
      # not encrypted? ignore and return the original message
      @stderr.write("process_json: cryptography error: #{e.message}\n".to_java_bytes)
      message << json
    rescue JSON::ParserError => e
      @stderr.write("process_json: parsing error: #{e.message}\n".to_java_bytes)
      message << json
    end
    message
  end

  def json?(info, is_request)
    if is_request
      return info.content_type == IRequestInfo::CONTENT_TYPE_JSON
    end
    return (info.stated_mime_type == "JSON" or info.inferred_mime_type == "JSON")
  end


  ################
  # Burp Methods #
  ################

  # String IMessageEditorTab::getTabCaption();
  def getTabCaption
    DISPLAY_NAME
  end

  # java.awt.Component IMessageEditorTab::getUiComponent()
  def getUiComponent
    @txt_input.get_component()
  end

  # boolean IMessageEditorTab::isEnabled(byte[] content, boolean isRequest)
  def isEnabled(content, is_request)
    return false if content.nil? or content.empty?

    if is_request
      info = @helper.analyze_request(content)
    else
      info = @helper.analyze_response(content)
    end
    return json?(info, is_request)
  end

  # void IMessageEditorTab::setMessage(byte[] content, boolean isRequest)
  def setMessage(content, is_request)
    return if content.nil? or content.empty?
    # In case we modified the content in the Crypto Helper tab, switched to
    # another tab and went back to this tab, we want the modified content
    # persistent and avoid decrypting the original content again:
    return if @txt_input.text_modified?

    if is_request
      info = @helper.analyze_request(content)
    else
      info = @helper.analyze_response(content)
    end
    headers = content[ 0..(info.get_body_offset - 1) ].to_s
    body = content[ info.get_body_offset..-1 ].to_s
    body = process_json(body, :decrypt) if json?(info, is_request)

    @txt_input.text = (headers + body).to_java_bytes
    @txt_input.editable = @editable
  end

  # byte[] IMessageEditorTab::getMessage()
  def getMessage
    is_request = @txt_input.text[0..3].to_s == "HTTP"

    if is_request
      info = @helper.analyze_request(@txt_input.text)
    else
      info = @helper.analyze_response(@txt_input.text)
    end
    headers = @txt_input.text[ 0..(info.get_body_offset - 1) ].to_s
    body = @txt_input.text[ info.get_body_offset..-1 ].to_s
    body = process_json(body, :encrypt) if json?(info, is_request)

    return (headers + body).to_java_bytes
  end

  # boolean IMessageEditorTab::isModified()
  def isModified
    return @txt_input.text_modified?
  end
end

class BurpExtender
  include IBurpExtender
  include IMessageEditorTabFactory
  include IIntruderPayloadProcessor
  include EncryptionHelper

  attr_reader :callbacks

  # void IBurpExtender::registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
  def registerExtenderCallbacks(callbacks)
    @callbacks = callbacks

    callbacks.setExtensionName(DISPLAY_NAME)
    callbacks.registerMessageEditorTabFactory(self)
    callbacks.registerIntruderPayloadProcessor(self)
  end

  # IMessageEditorTab IMessageEditorTabFactory::createNewInstance(
  #   IMessageEditorController controller,
  #   boolean editable)
  def createNewInstance(controller, editable)
    JSONDecryptorTab.new(@callbacks, editable)
  end

  # String IIntruderPayloadProcessor::getProcessorName();
  def getProcessorName
    DISPLAY_NAME
  end

  # public byte[] IIntruderPayloadProcessor::processPayload(byte[] currentPayload,
  #                                                         byte[] originalPayload,
  #                                                         byte[] baseValue)
  def processPayload(currentPayload, originalPayload, baseValue)
    return currentPayload if currentPayload.nil? or currentPayload.empty?
    payload = encode_b64(encrypt(currentPayload.to_s))
    return payload.to_java_bytes
  end
end

