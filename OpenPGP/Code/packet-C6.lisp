;;;; BlackLight/OpenPGP/packet-C6.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; C6 is the first byte in a PUBLIC-KEY-PACKET.
;;;; This file contains Lisp code that implements three functions:
;;;; build-packet-C6-body takes a C6 field list and returns a C6 byte list.
;;;; parse-packet-C6-body takes a C6 byte list and returns a C6 field list.
;;;; packet-C6-okayp tests build-packet-C6-body and parse-packet-C6-body.
;;;; 
;;;; C6 field list
;;;; packet-name: symbol, 'PUBLIC-KEY-PACKET
;;;; header-type: symbol, specifies the type of header to be used
;;;; version-no: symbol, specifies the C6-packet version
;;;; date: string, specifies date and time the key was created
;;;; algorithm: symbol, specifies the public-key algorithm for the key
;;;; modulus: integer, specifies the public key modulus
;;;; exponent: integer, specifies the public key exponent
;;;;   Example:
;;;;     'PUBLIC-KEY-PACKET
;;;;     'NEW-HEADER-3
;;;;     'VERSION-4
;;;;     "2011-Jun-25 07:00:00 UTC"
;;;;     'RSA-ENCR-ONLY
;;;;     279066392318254818651812875010165680267
;;;;     123029831480589083068383205275953423357
;;;;
;;;; C6 byte list
;;;; version-no: one byte, specifies the C6-packet version
;;;; key-time: four bytes, 32-bit integer, 1970 epoch seconds
;;;; pub-key-alg: one byte, specifies the public-key algorithm
;;;; mpi-bits: two bytes, the number of bits in the mpi-int integer
;;;; mpi-int: n bytes, specifies the public key modulus
;;;; mpi-bits: two bytes, the number of bits in the mpi-int integer
;;;; mpi-int: n bytes, specifies the public key exponent
;;;;


;;;
;;; build-packet-C6-body
;;; takes a C6 field list f and returns a C6 byte list.
;;;

(defun build-packet-C6-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (not (= 5 (length f))) (error "list f must have 5 elements"))
  (if (not (symbolp (nth 0 f))) (error "version-no must be a symbol"))
  (if (not (stringp (nth 1 f))) (error "key-time must be a string"))
  (if (not (symbolp (nth 2 f))) (error "pub-key-alg must be a symbol"))
  (if (not (integerp (nth 3 f))) (error "mpi-int must be an integer"))
  (if (not (integerp (nth 4 f))) (error "mpi-int must be an integer"))
  (let ((mod-bits) (mod-bytes) (exp-bits) (exp-bytes))
    (setf mod-bits (ceiling (log (nth 3 f) 2)))
    (setf mod-bytes (ceiling (log (nth 3 f) 256)))
    (setf exp-bits (ceiling (log (nth 4 f) 2)))
    (setf exp-bytes (ceiling (log (nth 4 f) 256)))
    (append (list (version-type-code (nth 0 f)))
	    (split-int 4 (encode-epoch1970-secs (nth 1 f)))
	    (list (public-key-algorithm-code (nth 2 f)))
	    (split-int 2 mod-bits)
	    (split-int mod-bytes (nth 3 f))
	    (split-int 2 exp-bits)
	    (split-int exp-bytes (nth 4 f)))))


;;;
;;; parse-packet-C6-body
;;; takes a C6 byte list b and returns a C6 field list.
;;;

(defun parse-packet-C6-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (let ((mbits) (mlen))
    (setf mbits (unite-int (subseq b 6 8)))
    (setf mlen (ceiling (/ mbits 8.0)))
    (list (version-type-symbol (nth 0 b))
	  (decode-epoch1970-secs (unite-int (subseq b 1 5)))
	  (public-key-algorithm-symbol (nth 5 b))
	  (unite-int (subseq b 8 (+ 8 mlen)))
	  (unite-int (subseq b (+ 10 mlen) (length b))))))


;;;
;;; packet-C6-okayp
;;; tests build-packet-C6-body and parse-packet-C6-body
;;;

(defun packet-C6-okayp ()
  (let ((x) (y) (z))
    (setf x (list 'VERSION-3
		  (epoch1970-timestamp)
		  'RSA-ENCR-SIGN
		  (random (expt 2 1022))
		  (random (expt 2 1020))))
    (setf y (build-packet-C6-body x))
    (setf z (parse-packet-C6-body y))
    (equal x z)))


