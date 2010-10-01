(defproject ring-basic-authentication "0.0.1-SNAPSHOT"
  :description "Ring middleware for basic authentication."
  
  :dependencies [[org.clojure/clojure "1.2.0"]
                 [org.clojure/clojure-contrib "1.2.0"]
                 [clj-base64 "0.0.0-SNAPSHOT"]]
  
  :dev-dependencies [[swank-clojure "1.2.1"]
                     [autodoc "0.7.1"]]
  
  :autodoc {:description "Ring middleware to enforce basic authentication as described in RFC2617 section 2."
            :copyright "Copyright (c) Remco van 't Veer."
            :web-src-dir "http://github.com/remvee/ring-basic-authentication/blob/"})
