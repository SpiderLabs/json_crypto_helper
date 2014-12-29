json_crypto_helper
==================

Ruby based Burp extension for JSON Encryption/Decryption

## Install
```bash
git clone https://github.com/SpiderLabs/json_crypto_helper.git
```

It is recommended to use RVM:
```bash
cd [your json_crypto_helper dir]
rvm --ruby-version use jruby@burp --create
```

## Run Burp on command line
```bash
cd [your json_crypto_helper dir]
JRUBY_HOME=$MY_RUBY_HOME java -XX:MaxPermSize=1G -Xmx1g -Xms1g -jar [burp_dir]/burpsuite_pro_vx.x.x.jar
```

## Load the extension in Burp
* Configure Burp Suite Extender tool (Options tab): specify the path where the JRuby jar is installed. If you’re using RVM, it should be in your RVM project path, commonly installed here: $HOME/.rvm/rubies/jruby-x.x.x/lib/jruby.jar.
* Select Add in the Extensions tab.
* Select the extension type Ruby.
* Select the json_crypto_helper.rb file.

You should see your new extension showing up in the list.

## Author
Christophe De La Fuente - at gmail: chrisdlf.dev
