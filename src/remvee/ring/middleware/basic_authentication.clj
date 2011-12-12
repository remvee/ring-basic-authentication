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

  The authenticate function is called with two parameters, the
  username and password, and should return a value when the login is
  valid.

  The realm is a descriptive string visible to the visitor.  It,
  together with the canonical root URL, defines the protected resource
  on the server.

  The denied-response is a ring response structure which will be
  returned when authorization fails.  The appropriate status and
  authentication headers will be merged into it.  It defaults to plain
  text 'access denied' response."
  
  {:test
   (fn []
     (do
       ;; authorization success
       (is (= :pass ((wrap-basic-authentication (fn [_] :pass)
                                                #(and (= %1 "tester")
                                                      (= %2 "secret")))
                     {:headers {"authorization"
                                (str "Basic " (base64/encode-str "tester:secret"))}})))

       ;; authorization success with username and password available
       (let [handler (wrap-basic-authentication identity (constantly true))
	     req {:headers {"authorization" (str "Basic " (base64/encode-str "tester:secret"))}}
	     resp (handler req)]
	 (is (= "tester" (get-in resp [:params :basic-auth-user])))
	 (is (= "secret" (get-in resp [:params :basic-auth-pass]))))

       ;; authorization failure
       (let [f (wrap-basic-authentication (fn [_] :pass)
                                          #(and (= %1 "tester")
                                                (= %2 "secret")))
             r (f {:headers {}})]
         (is (= 401 (:status r)))
         (is (= "access denied" (:body r)))
         (is (re-matches #".*\"restricted area\"" (get (:headers r) "WWW-Authenticate"))))

       ;; fancy authorization failure
       (let [f (wrap-basic-authentication (fn [_] :pass)
                                          #(and (= %1 "tester")
                                                (= %2 "secret"))
                                          "test realm"
                                          {:headers {"Content-Type" "test/mime"}
                                           :body "test area not accessable"})]
         (let [r (f {:headers {}})]
           (is (= 401 (:status r)))
           (is (= "test area not accessable" (:body r)))
           (is (= "test/mime" (get (:headers r) "Content-Type")))
           (is (get (:headers r) "WWW-Authenticate"))
           (is (re-matches #".*\"test realm\"" (get (:headers r) "WWW-Authenticate")))))))}

  ([app authenticate]
     (wrap-basic-authentication app authenticate nil nil))
  ([app authenticate realm]
     (wrap-basic-authentication app authenticate realm nil))
  ([app authenticate realm denied-response]
     (fn [req]
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
           (app (-> req
		    (assoc-in [:params :basic-auth-user] name)
		    (assoc-in [:params :basic-auth-pass] pass)))
           (assoc (merge {:headers {"Content-Type" "text/plain"}
                          :body    "access denied"}
                         denied-response)
             :status  401
             :headers (merge (:headers denied-response)
                             {"WWW-Authenticate" (format "Basic realm=\"%s\""
                                                         (or realm "restricted area"))})))))))

