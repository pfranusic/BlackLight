;;;; BlackLight/OpenPGP/packet-C4.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; C4 is the first byte in a ONE-PASS-SIGNATURE-PACKET.
;;;; This file contains Lisp code that implements three functions:
;;;; build-packet-C4-body takes a C4 field list and returns a C4 byte list.
;;;; parse-packet-C4-body takes a C4 byte list and returns a C4 field list.
;;;; packet-C4-okayp tests build-packet-C4-body and parse-packet-C4-body.
;;;; 
;;;; C4 field list
;;;; 0: ONE-PASS-SIGNATURE-PACKET
;;;; 1: header-type
;;;; 2: version-no: symbol, signifies the version of the signature packet.
;;;; 3: signet-type: symbol, signifies the signature type.
;;;; 4: hash-alg: symbol, specifies the hash algorithm.
;;;; 5: pub-key-alg: symbol, specifies the public-key algorithm.
;;;; 6: pub-key-id: string, represents a 64-bit Key ID.
;;;; 7: with which the hash of the subsequent OpenPGP message is signed.
;;;; 8: last-C4: integer, represents a boolean value, where
;;;;    (/= 0) means "This is the last C4 packet" and
;;;;    (= 0) means "This is NOT the last C4 packet".
;;;;


;;;
;;; build-packet-C4-body
;;; takes a C4 field list p and returns a C4 byte list m.
;;;

(defun build-packet-C4-body (p)
  (if (not (listp p)) (error "p is not a list."))
  (if (not (= 6 (length p))) (error "list p must have 6 elements"))
  (if (not (symbolp (nth 0 p))) (error "version-type must be a symbol"))
  (if (not (symbolp (nth 1 p))) (error "signet-type must be a symbol"))
  (if (not (symbolp (nth 2 p))) (error "hash-alg must be a symbol"))
  (if (not (symbolp (nth 3 p))) (error "pub-key-alg must be a symbol"))
  (if (not (stringp (nth 4 p))) (error "pub-key-id must be an string"))
  (if (not (integerp (nth 5 p))) (error "last-C4 must be an integer."))
  (append (list (version-type-code (nth 0 p)))
	  (list (signature-type-code (nth 1 p)))
	  (list (hash-algorithm-code (nth 2 p)))
	  (list (public-key-algorithm-code (nth 3 p)))
	  (split-int 8 (hex-int (nth 4 p)))
	  (list (nth 5 p))))


;;;
;;; parse-packet-C4-body
;;; takes a C4 message list m and returns a C4 packet list p.
;;;

(defun parse-packet-C4-body (m)
  (if (not (blistp m)) (error "m must be a list of bytes."))
  (list (version-type-symbol (nth 0 m))
	(signature-type-symbol (nth 1 m))
	(hash-algorithm-symbol (nth 2 m))
	(public-key-algorithm-symbol (nth 3 m))
	(format nil "~16,'0X" (unite-int (subseq m 4 12)))
	(nth 12 m)))


;;;
;;; one-pass-signature-packet-p
;;; returns T iff p is a one-pass-signature-packet.
;;; 0: ONE-PASS-SIGNATURE-PACKET
;;; 1: header-type
;;; 2: version-no: symbol, signifies the version of the signature packet.
;;; 3: signet-type: symbol, signifies the signature type.
;;; 4: hash-alg: symbol, specifies the hash algorithm.
;;; 5: pub-key-alg: symbol, specifies the public-key algorithm.
;;; 6: pub-key-id: string, represents a 64-bit Key ID.
;;;     with which the hash of the subsequent OpenPGP message is signed.
;;; 7: last-C4: integer, represents a boolean value, where
;;;    (/= 0) means "This is the last C4 packet" and
;;;    (= 0) means "This is NOT the last C4 packet".
;;; Example:  (ONE-PASS-SIGNATURE-PACKET OLD-HEADER-2 
;;;            VERSION-3 BINARY-SIGNATURE SHA-256
;;;            RSA-ENCR-SIGN "DE85CA0B6039F25B" 1)
;;;

(defun one-pass-signature-packet-p (p)
  (and (listp p)
       (= 8 (length p))
       (symbolp (nth 0 p))
       (equal 'ONE-PASS-SIGNATURE-PACKET (nth 0 p))
       (symbolp (nth 1 p))
       (symbolp (nth 2 p))
       (equal 'VERSION-3 (nth 2 p))
       (symbolp (nth 3 p))
       (equal 'BINARY-SIGNATURE (nth 3 p))
       (symbolp (nth 4 p))
       (equal 'SHA-256 (nth 4 p))
       (symbolp (nth 5 p))
       (equal 'RSA-ENCR-SIGN (nth 5 p))
       (hex-stringp (nth 6 p))
       (integerp (nth 7 p))
       (= 1 (nth 7 p))))


;;;
;;; packet-C4-okayp
;;; tests build-packet-C4-body and parse-packet-C4-body.
;;;

(defun packet-C4-okayp ()
  (let ((x) (y) (z))
    (setf x (list
	     'VERSION-3
	     'BINARY-SIGNATURE
	     'SHA-256
	     'RSA-ENCR-SIGN
	     "FEDCBA9807654321"
	     0))
    (setf y (build-packet-C4-body x))
    (setf z (parse-packet-C4-body y))
    (equal x z)))


