;; Copyright (c) Remco van 't Veer. All rights reserved.
;; The use and distribution terms for this software are covered by the Eclipse
;; Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
;; can be found in the file epl-v10.html at the root of this distribution.  By
;; using this software in any fashion, you are agreeing to be bound by the
;; terms of this license.  You must not remove this notice, or any other, from
;; this software.

(ns remvee.ring.middleware.basic-authentication
  "HTTP basis authentication middleware for ring."
  {:author "Remco van 't Veer"}
  (:use clojure.test
        [remvee.base64 :as base64]))

(defn wrap-basic-authentication
  "Wrap response with a basic authentication challenge as described in
  RFC2617 section 2.

  The realm is a descriptive string visible to the visitor.  It,
  together with the canonical root URL, defines the protected resource
  on the server.

  The authenticate function is called with two parameters, the
  username and password, and should return a value when the login is
  valid.

  The optional matcher function determines if authorization is
  required.  Is receives the original request map."
  
  {:test
   (fn []
     (let [f (wrap-basic-authentication (fn [_] :pass)
                                        "test realm"
                                        #(and (= %1 "tester")
                                              (= %2 "secret")))]
       (let [r (f {:headers {}})]
         (is (= 401 (:status r)))
         (is (= "Need authorization .." (:body r)))
         (is (not (empty? (re-find #"test realm"
                                   (get (:headers r)
                                        "WWW-Authenticate"))))))
       (let [r (f {:headers
                   {"authorization"
                    (str "Basic "
                         (base64/encode-str "tester:secret"))}})]
         (is (= :pass r)))))}
  
  ([app realm authenticate]
     (wrap-basic-authentication app realm authenticate nil))
  ([app realm authenticate matcher]
     (fn [req]
       (if (and matcher (not (matcher req)))
         (app req)
         (let [auth ((:headers req) "authorization")
               cred (and auth
                         (base64/decode-str
                          (last
                           (re-find #"^Basic (.*)$" auth))))
               name (and cred
                         (last
                          (re-find #"^(.*):" cred)))
               pass (and cred
                         (last
                          (re-find #":(.*)$" cred)))]
           (if (authenticate name pass)
             (app req)
             {:status  401
              :headers {"WWW-Authenticate" (format "Basic realm=\"%s\""
                                                   realm)}
              :body    "Need authorization .."}))))))

