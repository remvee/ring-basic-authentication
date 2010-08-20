(ns run
  (:use [remvee.ring.middleware.basic-authentication] :reload-all)
  (:use [clojure.test]))

(deftest all
  (run-tests 'remvee.ring.middleware.basic-authentication))