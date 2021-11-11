;; Copyright (c) Remco van 't Veer. All rights reserved.
;; The use and distribution terms for this software are covered by the Eclipse
;; Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php) which
;; can be found in the file epl-v10.html at the root of this distribution.  By
;; using this software in any fashion, you are agreeing to be bound by the
;; terms of this license.  You must not remove this notice, or any other, from
;; this software.

(ns ring.middleware.basic-authentication-test
  (:require [clojure.test :refer :all]
            [ring.middleware.basic-authentication :as sut]))

(defn- encode-base64 [v]
  (#'sut/encode-base64 v))

(deftest wrap-basic-authentication
  (testing "authorization successful"
    (let [r ((sut/wrap-basic-authentication identity
                                            #(and (= %1 "tester")
                                                  (= %2 "secret")
                                                  "token"))
             {:headers {"authorization"
                        (str "Basic " (encode-base64 "tester:secret"))}})]
      (is (= "token" (:basic-authentication r)))))

  (testing "authorization successful with password containing colon"
    (let [r ((sut/wrap-basic-authentication identity
                                            #(and (= %1 "tester")
                                                  (= %2 "the:secret")
                                                  "token"))
             {:headers {"authorization"
                        (str "Basic " (encode-base64 "tester:the:secret"))}})]
      (is (= "token" (:basic-authentication r)))))

  (testing "when user and password empty"
    (is (= :pass
           ((sut/wrap-basic-authentication (fn [_] :pass) #(and (= %1 "")
                                                                (= %2 "")))
            {:headers {"authorization" (str "Basic " (encode-base64 ":"))}}))))

  (testing "authorization failure with bad credentials"
    (let [f (sut/wrap-basic-authentication identity (fn [_ _]))
          r (f {:headers {}})]
      (is (= 401 (:status r)))
      (is (= "access denied" (:body r)))
      (is (re-matches #".*\"restricted area\"" (get (:headers r) "WWW-Authenticate")))
      (let [r (f {:request-method :head, :headers {}})]
        (is (nil? (:body r)) "head request yields no body"))))

  (testing "authorization failure with unacceptable"
    (let [r ((sut/wrap-basic-authentication identity (fn [_ _]))
             {:headers {"authorization" "Basic this is unacceptable!"}})]
      (is (= 401 (:status r)))))

  (testing "authorization failure with empty credentials"
    (let [r ((sut/wrap-basic-authentication identity (fn [_ _]))
             {:headers {"authorization" (str "Basic " (encode-base64 ":"))}})]
      (is (= 401 (:status r)))))

  (testing "overwrite default status code"
    (let [f (sut/wrap-basic-authentication identity (fn [_ _]) nil {:status 999})
          r (f {:headers {}})]
      (is (= 999 (:status r)))))

  (testing "overwrite default header"
    (let [f (sut/wrap-basic-authentication identity (fn [_ _]) nil {:headers {"WWW-Authenticate" nil}})
          r (f {:headers {}})]
      (is (nil? (get-in r [:headers "WWW-Authenticate"])))))

  (testing "fancy authorization failure"
    (let [f (sut/wrap-basic-authentication identity (fn [_ _])
                                           "test realm"
                                           {:headers {"Content-Type" "test/mime"}
                                            :body "test area not accessable"})
          r (f {:headers {}})]
      (is (= 401 (:status r)))
      (is (= "test area not accessable" (:body r)))
      (is (= "test/mime" (get (:headers r) "Content-Type")))
      (is (get (:headers r) "WWW-Authenticate"))
      (is (re-matches #".*\"test realm\"" (get (:headers r) "WWW-Authenticate")))

      (let [r (f {:request-method :head, :headers {}})]
        (is (nil? (:body r)) "head request yields no body")))))
