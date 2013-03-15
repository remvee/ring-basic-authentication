;; Copyright (c) Remco van 't Veer. All rights reserved.
;; The use and distribution terms for this software are covered by the Eclipse
;; Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
;; can be found in the file epl-v10.html at the root of this distribution.  By
;; using this software in any fashion, you are agreeing to be bound by the
;; terms of this license.  You must not remove this notice, or any other, from
;; this software.

(ns ring.middleware.basic-authentication
  "HTTP basic authentication middleware for ring."
  {:author "Remco van 't Veer"}
  (:use clojure.test)
  (:require [clojure.string :as s]
            [clojure.data.codec.base64 :as base64]))

(defn- byte-transform
  "Used to encode and decode strings.  Returns nil when an exception
  was raised."
  [direction-fn string]
  (try
    (reduce str (map char (direction-fn (.getBytes string))))
    (catch Exception _)))

(defn- encode-base64
  "Will do a base64 encoding of a string and return a string."
  [^String string]
  (byte-transform base64/encode string))

(defn- decode-base64
  "Will do a base64 decoding of a string and return a string."
  [^String string]
  (byte-transform base64/decode string))

(defn wrap-basic-authentication
  "Wrap response with a basic authentication challenge as described in
  RFC2617 section 2.

  The authenticate function is called with two parameters, the userid
  and password, and should return a value when the login is valid.  This
  value is added to the request structure with the :basic-authentication
  key.

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
       (let [r ((wrap-basic-authentication identity
                                           #(and (= %1 "tester")
                                                 (= %2 "secret")
                                                 "token"))
                {:headers {"authorization"
                           (str "Basic " (encode-base64 "tester:secret"))}})]
         ;; authorization success
         (is r)

         ;; authorization success adds basic-authentication on request map
         (is (= "token" (:basic-authentication r))))

       ;; authorization success when expecting empty user and password
       (is (= :pass
              ((wrap-basic-authentication (fn [_] :pass) #(and (= %1 "")
                                                               (= %2 "")))
               {:headers {"authorization" (str "Basic " (encode-base64 ":"))}})))

       ;; authorization failure with bad credentials
       (let [f (wrap-basic-authentication identity (fn [_ _]))
             r (f {:headers {}})]
         (is (= 401 (:status r)))
         (is (= "access denied" (:body r)))
         (is (re-matches #".*\"restricted area\"" (get (:headers r) "WWW-Authenticate"))))

       ;; authorization failure with unacceptable
       (let [r ((wrap-basic-authentication identity (fn [_ _]))
                {:headers {"authorization" "Basic this is unacceptable!"}})]
         (is (= 401 (:status r))))

       ;; authorization failure with empty credentials
       (let [r ((wrap-basic-authentication identity (fn [_ _]))
                {:headers {"authorization" (str "Basic " (encode-base64 ":"))}})]
         (is (= 401 (:status r))))

       ;; fancy authorization failure
       (let [f (wrap-basic-authentication identity (fn [_ _])
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
             cred (and auth (decode-base64 (last (re-find #"^Basic (.*)$" auth))))
             [user pass] (and cred (s/split (str cred) #":"))]
         (if-let [token (and cred (authenticate (str user) (str pass)))]
           (app (assoc req :basic-authentication token))
           (assoc (merge {:headers {"Content-Type" "text/plain"}
                          :body "access denied"}
                         denied-response)
             :status  401
             :headers (merge (:headers denied-response)
                             {"WWW-Authenticate" (format "Basic realm=\"%s\""
                                                         (or realm "restricted area"))})))))))
