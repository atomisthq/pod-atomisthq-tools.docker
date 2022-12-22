(ns user
  (:require [babashka.pods :as pods]
            [clojure.edn :as edn]))

(pods/load-pod 'atomisthq/tools.docker "0.1.0")
(require '[pod.atomisthq.docker :as docker])

;; parse image names using github.com/docker/distribution 
;; turns golang structs into clojure maps
(docker/parse-image-name "gcr.io/whatever:tag")
;; automatically turns golang errors into Exceptions
(try
  (docker/parse-image-name "gcr.io/whatever/:tag")
  (catch Exception e
    ;; invalid reference format
    (println (.getMessage e))))

;; parse dockerfiles using github.com/moby/buildkit
;; returns the Result struct transformed to a clojure map
(docker/parse-dockerfile "FROM \\\n    gcr.io/whatever:tag\nCMD [\"run\"]")

;; run sbom generation on local image
(docker/sbom "vonwig/clojure-base:jdk17" (fn [event] (println event)))

(defn transact-hashes [{:keys [image digest diff-id->digest transaction-url token]}]
  (println "")
  (let [all-hashes (atom [])]
    (docker/hashes image (fn [event]
                           (if (= "done" (:status event))
                             (let [tx-data (->> @all-hashes
                                                (mapcat (fn [{:keys [path hash diff-id]}]
                                                          (let [blob-digest (diff-id->digest diff-id)]
                                                            [{:schema/entity blob-digest
                                                              :schema/entity-type :docker.image/blob
                                                              :docker.image.blob/digest digest}
                                                             {:docker.image.blob.file/sha256 hash
                                                              :docker.image.blob.file/blob digest}]))))]
                               (println "transact " tx-data)
                               (println "transact " [{:docker.image/digest digest
                                                      :schema/entity-type :docker/image
                                                      :malware.status/indexed :malware.status.indexed/complete}]))
                             (swap! all-hashes conj event))))))

