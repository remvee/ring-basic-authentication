(defproject ring-basic-authentication "1.1.0-SNAPSHOT"
  :description "Ring middleware to enforce basic authentication as described in RFC2617 section 2."
  :url "https://github.com/remvee/ring-basic-authentication/"

  :license {:name "Eclipse Public License - v 1.0"
            :url  "http://opensource.org/licenses/eclipse-1.0.php"}

  :dependencies [[org.clojure/clojure "1.10.1"]]
  :plugins [[lein-codox "0.10.7"]]

  :codox {:output-path    "doc"
          :source-dir-uri ""
          :source-uri     "https://github.com/remvee/ring-basic-authentication/blob/{git-commit}/{filepath}#L{line}"})
