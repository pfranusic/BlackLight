;;;; BlackLight/OpenPGP/packet-C1.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; C1 is the first byte in a PKE-SESSION-KEY-PACKET.
;;;; This file contains Lisp code that implements three functions:
;;;; build-packet-C1-body takes a C1 field list and returns a C1 byte list.
;;;; parse-packet-C1-body takes a C1 byte list and returns a C1 field list.
;;;; packet-C1-okayp tests build-packet-C1-body and parse-packet-C1-body.
;;;; 
;;;; C1 field list
;;;; packet-tag: symbol, PKE-SESSION-KEY-PACKET
;;;; header-type: symbol,
;;;; version-no: symbol, specifies the C1-packet version
;;;; pub-key-id: string, 16 hexadecimal digits, specifies the 64-bit Key ID
;;;; pub-key-alg: symbol, specifies the public-key algorithm
;;;; mpi-int: integer, 1024+ bits, specifies an encrypted session key
;;;;
;;;; C1 byte list
;;;; version-no: one byte, specifies the C1-packet version
;;;; pub-key-id: eight bytes, low-order 64 bits of the V4 fingerprint
;;;; pub-key-alg: one byte, specifies the public-key algorithm
;;;; mpi-bits: two bytes, the number of significant bits in the mpi-int integer
;;;; mpi-int: n bytes, represents the public-key signature of the hash value
;;;;


;;;
;;; build-packet-C1-body
;;; takes a C1 field list f and returns a C1 byte list.
;;;

(defun build-packet-C1-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (not (= 4 (length f))) (error "list f must have 4 elements"))
  (if (not (symbolp (nth 0 f))) (error "version-no must be a symbol"))
  (if (not (stringp (nth 1 f))) (error "pub-key-id must be a string"))
  (if (not (symbolp (nth 2 f))) (error "pub-key-alg must be a symbol"))
  (if (not (integerp (nth 3 f))) (error "mpi-int must be an integer"))
  (let ((mpi-bits) (mpi-bytes))
    (setf mpi-bits (ceiling (log (nth 3 f) 2)))
    (setf mpi-bytes (ceiling (log (nth 3 f) 256)))
    (append (list (version-type-code (nth 0 f)))
	    (split-int 8 (hex-int (nth 1 f)))
	    (list (public-key-algorithm-code (nth 2 f)))
	    (split-int 2 mpi-bits)
	    (split-int mpi-bytes (nth 3 f)))))


;;;
;;; parse-packet-C1-body
;;; takes a C1 byte list b and returns a C1 field list.
;;;

(defun parse-packet-C1-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (list (version-type-symbol (nth 0 b))
	(format nil "~16,'0X" (unite-int (subseq b 1 9)))
	(public-key-algorithm-symbol (nth 9 b))
	(unite-int (subseq b 12 (length b)))))


;;;
;;; pke-session-key-packet-p
;;; returns T iff p is a pke-session-key-packet.
;;; 0: PKE-SESSION-KEY-PACKET, symbol
;;; 1: header type, symbol
;;; 2: VERSION-3, symbol
;;; 3: key-id, hex-string
;;; 4: RSA-ENCR-SIGN, symbol
;;; 5: huge integer
;;;

(defun pke-session-key-packet-p (p)
  (and (listp p)
       (= 6 (length p))
       (symbolp (nth 0 p))
       (symbolp (nth 1 p))
       (symbolp (nth 2 p))
       (hex-stringp (nth 3 p))
       (symbolp (nth 4 p))
       (integerp (nth 5 p))
       (equal 'PKE-SESSION-KEY-PACKET (nth 0 p))
       (equal 'VERSION-3 (nth 2 p))
       (= 16 (length (nth 3 p)))
       (equal 'RSA-ENCR-SIGN (nth 4 p))
       (in-between 511 (log (nth 5 p) 2) 8193)))


;;;
;;; packet-C1-okayp
;;; tests build-packet-C1-body and parse-packet-C1-body
;;;

(defun packet-C1-okayp ()
  (let ((x) (y) (z))
    (setf x (list 'VERSION-3
		  "7D1D7001BDFFDB56"
		  'RSA-ENCR-SIGN
		  (random (expt 2 (+ 1020 (random 5))))))
    (setf y (build-packet-C1-body x))
    (setf z (parse-packet-C1-body y))
    (equal x z)))


