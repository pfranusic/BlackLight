;;;; BlackLight/OpenPGP/packet-C8.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; C8 is the first byte in a COMPRESSED-DATA-PACKET.
;;;; This file contains Lisp code that implements three functions:
;;;; build-packet-C8-body takes a C8 field list and returns a C8 byte list.
;;;; parse-packet-C8-body takes a C8 byte list and returns a C8 field list.
;;;; packet-C8-okayp tests build-packet-C8-body and parse-packet-C8-body.
;;;; 
;;;; C8 field list
;;;; 0: COMPRESSED-DATA-PACKET, symbol
;;;; 1: header-type, symbol
;;;; 2: compr-alg, symbol, represents the compression algorithm to be used.
;;;; 3: compr-data, list of bytes, the compressed data.
;;;; 


;;;
;;; build-packet-C8-body
;;; takes a nested packet list p with compressed data
;;; and returns a flat message list m with compressed data.
;;;

(defun build-packet-C8-body (p)
  (if (not (listp p)) (error "p is not a list"))
  (if (not (symbolp (nth 0 p))) (error "p[0] must be a symbol"))
  (if (not (listp (nth 1 p))) (error "p[1] must be a list"))
  (let ((compr-data))
    (if (not (equal (nth 0 p) 'ZLIB))
	(error "BlackLight OpenPGP supports only ZLIB at this time"))
    (setf compr-data (nth 1 p))
    (append (list 2) compr-data)))


;;;
;;; parse-packet-C8-body
;;; takes a flat message list m with compressed data
;;; and returns a nested packet list p with compressed data.
;;;

(defun parse-packet-C8-body (m)
  (if (not (listp m)) (error "m is not a list."))
  (let ((compr-data))
    (if (/= 2 (nth 0 m))
	(error "BlackLight OpenPGP supports only ZLIB at this time"))
    (setf compr-data (subseq m 1 (length m)))
    (list 'ZLIB compr-data)))


;;;
;;; compressed-data-packet-p
;;; returns T iff p is a compressed-data-packet.
;;; 0: COMPRESSED-DATA-PACKET
;;; 1: header type
;;; 2: compression algorithm, symbol (ZLIB)
;;; 3: uncompressed data
;;;

(defun compressed-data-packet-p (p)
  (and (listp p)
       (= 4 (length p))
       (symbolp (nth 0 p))
       (equal 'COMPRESSED-DATA-PACKET (nth 0 p))
       (symbolp (nth 1 p))
       (symbolp (nth 2 p))
       (equal 'ZLIB (nth 2 p))
       (blistp (nth 3 p))))


;;;
;;; packet-C8-okayp
;;; returns T iff x and z are equal.
;;;

(defun packet-C8-okayp ()
  (let ((x) (y) (z))
    (setf x (list 'ZLIB
		  '(97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 
		    97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 
		    97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 
		    97 97 97 97 97 97 97 97 97 97 97 97 97 97 97 97)))
    (setf y (build-packet-C8-body x))
    (setf z (parse-packet-C8-body y))
    (equal x z)))


