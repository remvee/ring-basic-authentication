(defproject ring-basic-authentication "0.0.3"
  :description "Ring middleware for basic authentication."
  
  :dependencies [[org.clojure/clojure "1.3.0"]
                 [clj-base64 "0.0.2"]]
  
  :autodoc {:description "Ring middleware to enforce basic authentication as described in RFC2617 section 2."
            :copyright "Copyright (c) Remco van 't Veer."
            :web-src-dir "http://github.com/remvee/ring-basic-authentication/blob/"})
