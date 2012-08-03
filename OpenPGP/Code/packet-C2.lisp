;;;; BlackLight/OpenPGP/packet-C2.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; C2 is the first byte in a version 4 SIGNATURE-PACKET.
;;;; This file contains Lisp code that implements three functions:
;;;; build-packet-C2-body takes a C2 field list and returns a C2 byte list.
;;;; parse-packet-C2-body takes a C2 byte list and returns a C2 field list.
;;;; packet-C2-okayp tests build-packet-C2-body and parse-packet-C2-body.
;;;; 
;;;; C2 field list
;;;; 0: SIGNATURE-PACKET, symbol.
;;;; 1: header type, symbol.
;;;; 2: version-no: symbol, specifies the C2-packet version
;;;; 3: signet-type: symbol, specifies the signature type
;;;; 4: pub-key-alg: symbol, specifies the public-key algorithm
;;;; 5: hash-alg: symbol, specifies the message digest (hash) algorithm
;;;; 6: hashed-subs: list, zero or more lists
;;;; 7: unhash-subs: list, zero or more lists
;;;; 8: hash-msw: string, 4 hexadecimal digits, the 16 msb of the hash value
;;;; 9: mpi-int: integer, represents the public-key signature of the hash value
;;;; Example:
;;;;    SIGNATURE-PACKET
;;;;    NEW-HEADER-3
;;;;    VERSION-4
;;;;    POSITIVE-CERTIFICATION
;;;;    RSA-ENCR-SIGN
;;;;    SHA-256
;;;;    ((SUBPACKET-A ... ) (SUBPACKET-A ... ))
;;;;    ((SUBPACKET-A ... ) (SUBPACKET-A ... ))
;;;;    "F9C6"
;;;;    332380961503424150155463219807967773514
;;;;
;;;; C2 byte list (a byte is an 8-bit integer)
;;;; version-no: one byte, specifies the C2-packet version
;;;; signet-type: one byte, specifies the signature type
;;;; pub-key-alg: one byte, specifies the public-key algorithm
;;;; hash-alg: one byte, specifies the message digest (hash) algorithm
;;;; hashed-len: two bytes, specifies the number of bytes in the hashed-subs list
;;;; hashed-subs: zero or more bytes, subpacket data, subsequently hashed
;;;; unhash-len: two bytes, specifies the number of bytes in the unhash-subs list
;;;; unhash-subs: zero or more bytes, subpacket data, subsequently unhashed
;;;; hash-msw: two bytes, the 16 most-significant bits of the hash value
;;;; mpi-bits: two bytes, the number of significant bits in the mpi-int integer
;;;; mpi-int: n bytes, represents the public-key signature of the hash value
;;;;


;;;
;;; build-packet-C2-body
;;; given a C2 field list f, returns a C2 byte list.
;;;

(defun build-packet-C2-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (not (= 8 (length f))) (error "list f must have 8 elements"))
  (if (not (symbolp (nth 0 f))) (error "version-no must be a symbol"))
  (if (not (symbolp (nth 1 f))) (error "signet-type must be a symbol"))
  (if (not (symbolp (nth 2 f))) (error "pub-key-alg must be a symbol"))
  (if (not (symbolp (nth 3 f))) (error "hash-alg must be a symbol"))
  (if (not (listp (nth 4 f))) (error "hashed-subs must be a list"))
  (if (not (listp (nth 5 f))) (error "unhash-subs must be a list"))
  (if (not (stringp (nth 6 f))) (error "hash-msw must be a string"))
  (if (not (integerp (nth 7 f))) (error "mpi-int must be an integer"))
  (let ((mpi-bits) (mpi-bytes) (hashed-subs) (unhash-subs))
    (setf mpi-bits (ceiling (log (nth 7 f) 2)))
    (setf mpi-bytes (ceiling (log (nth 7 f) 256)))
    (setf hashed-subs (build-subpacket-block (nth 4 f)))
    (setf unhash-subs (build-subpacket-block (nth 5 f)))
    (append (list (version-type-code (nth 0 f)))
	    (list (signature-type-code (nth 1 f)))
	    (list (public-key-algorithm-code (nth 2 f)))
	    (list (hash-algorithm-code (nth 3 f)))
	    (split-int 2 (length hashed-subs))
	    hashed-subs
	    (split-int 2 (length unhash-subs))
	    unhash-subs
	    (split-int 2 (hex-int (nth 6 f)))
	    (split-int 2 mpi-bits)
	    (split-int mpi-bytes (nth 7 f)))))


;;;
;;; parse-packet-C2-body
;;; given a C2 byte list b, returns a C2 field list.
;;;

(defun parse-packet-C2-body (b)
  (if (not (listp b)) (error "b must be a list"))
  (let ((hlen) (ulen) (clen))
    (setf hlen (unite-int (subseq b 4 6)))
    (setf ulen (unite-int (subseq b (+ 6 hlen) (+ 8 hlen))))
    (setf clen (+ hlen ulen))
    (list (version-type-symbol (nth 0 b))
	  (signature-type-symbol (nth 1 b))
	  (public-key-algorithm-symbol (nth 2 b))
	  (hash-algorithm-symbol (nth 3 b))
	  (parse-subpacket-block (subseq b 6 (+ 6 hlen)))
	  (parse-subpacket-block (subseq b (+ 8 hlen) (+ 8 clen)))
	  (format nil "~4,'0X" (unite-int (subseq b (+ 8 clen) (+ 10 clen))))
	  (unite-int (subseq b (+ 12 clen) (length b))))))


;;;
;;; binary-signature-packet-p
;;; returns T iff p is a binary-signature-packet.
;;; 0: SIGNATURE-PACKET, symbol.
;;; 1: header type, symbol.
;;; 2: version-no: symbol, specifies the C2-packet version
;;; 3: signet-type: symbol, specifies the signature type
;;; 4: pub-key-alg: symbol, specifies the public-key algorithm
;;; 5: hash-alg: symbol, specifies the message digest (hash) algorithm
;;; 6: hashed-subs: list, zero or more lists
;;; 7: unhash-subs: list, zero or more lists
;;; 8: hash-msw: string, 4 hexadecimal digits, the 16 msb of the hash value
;;; 9: mpi-int: integer, represents the public-key signature of the hash value
;;;

(defun binary-signature-packet-p (p)
  (and (listp p)
       (= 10 (length p))
       (symbolp (nth 0 p))
       (symbolp (nth 1 p))
       (symbolp (nth 2 p))
       (symbolp (nth 3 p))
       (symbolp (nth 4 p))
       (symbolp (nth 5 p))
       (listp (nth 6 p))
       (listp (nth 7 p))
       (hex-stringp (nth 8 p))
       (integerp (nth 9 p))
       (equal 'SIGNATURE-PACKET (nth 0 p))
       (equal 'VERSION-4 (nth 2 p))
       (equal 'BINARY-SIGNATURE (nth 3 p))
       (equal 'RSA-ENCR-SIGN (nth 4 p))
       (equal 'SHA-256 (nth 5 p))
       (equal 'SIGNATURE-CREATION-TIME (nth 1 (nth 0 (nth 6 p))))
       (equal 'ISSUER (nth 1 (nth 0 (nth 7 p))))
       (= 4 (length (nth 8 p)))
       (in-between 511 (log (nth 9 p) 2) 8193)))


;;;
;;; packet-C2-okayp
;;; tests build-packet-C2-body and parse-packet-C2-body.
;;;

(defun packet-C2-okayp ()
  (let ((x) (y) (z))
    (setf x '(VERSION-4
	      POSITIVE-CERTIFICATION
	      RSA-ENCR-SIGN
	      SHA-1
	      ((SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC")
	       (SUBPACKET-A KEY-FLAGS "101111")
	       (SUBPACKET-A PREFERRED-SYMMETRIC-ALGORITHMS AES-256 AES-192 AES-128 CAST5 TRIPLE-DES)
	       (SUBPACKET-A PREFERRED-HASH-ALGORITHMS SHA-1 SHA-256 RIPEMD-160)
	       (SUBPACKET-A PREFERRED-COMPRESSION-ALGORITHMS ZLIB BZIP2 ZIP)
	       (SUBPACKET-A FEATURES "1") (SUBPACKET-A KEY-SERVER-PREFERENCES "10000000"))
	      ((SUBPACKET-A ISSUER "F894450D1BBE6287"))
	      "2DA5"
	      113207580883489031307944736163806615720106520542998671911547322921937212208397828549245363811847998588319200518359172261868794079150950952449839689637495930685935753104260640913206789117991452217867070800683209062926063197046574813041676263466564061579657226312854070072278839444545838455596742458138365545844))
    (setf y (build-packet-C2-body x))
    (setf z (parse-packet-C2-body y))
    (equal x z)))


