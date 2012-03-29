(ns run
  (:use [ring.middleware.basic-authentication] :reload-all)
  (:use [clojure.test]))

(deftest all
  (run-tests 'ring.middleware.basic-authentication))
