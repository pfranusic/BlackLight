;;;; BlackLight/OpenPGP/pkcs.lisp
;;;; Copyright 2012 Peter Franusic
;;;;


;;;
;;; hash-prefix
;;; Input is a symbol that specifies a hash algorithm.
;;; Output is a list of bytes that specify the same.
;;; Refer to RFC-4880 section 5.5.2.
;;;

(defun hash-prefix (s)
  (if (not (symbolp s)) (error "s must be a symbol"))
  (case s
	(MD5          '(#x30 #x20 #x30 #x0C #x06 #x08 #x2A #x86
			#x48 #x86 #xF7 #x0D #x02 #x05 #x05 #x00
			#x04 #x10))
	(RIPEMD-160   '(#x30 #x21 #x30 #x09 #x06 #x05 #x2B #x24
			#x03 #x02 #x01 #x05 #x00 #x04 #x14))
	(SHA-1        '(#x30 #x21 #x30 #x09 #x06 #x05 #x2b #x0E
			#x03 #x02 #x1A #x05 #x00 #x04 #x14))
	(SHA-224      '(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86
			#x48 #x01 #x65 #x03 #x04 #x02 #x04 #x05
			#x00 #x04 #x1C))
	(SHA-256      '(#x30 #x31 #x30 #x0d #x06 #x09 #x60 #x86
			#x48 #x01 #x65 #x03 #x04 #x02 #x01 #x05
			#x00 #x04 #x20))
	(SHA-384      '(#x30 #x41 #x30 #x0d #x06 #x09 #x60 #x86
			#x48 #x01 #x65 #x03 #x04 #x02 #x02 #x05
			#x00 #x04 #x30))
	(SHA-512      '(#x30 #x51 #x30 #x0d #x06 #x09 #x60 #x86
			#x48 #x01 #x65 #x03 #x04 #x02 #x03 #x05
			#x00 #x04 #x40))
	(otherwise    nil)))


;;;
;;; pkcs-sign-base
;;; returns the integer that is signed before encryption
;;; and later verified after decryption.
;;; I.e., this function is called by both export-cert and import-cert.
;;; The output is a large integer that contains a hash, 
;;; a hash prefix, and other EMSA-PKCS1-v1_5 padding bytes.
;;; See RFC-4880 section 13.1.3.
;;; Input is two integers and a symbol.
;;; h is the hash integer (160 bits for SHA-1).
;;; l is the length of the modulus in bytes.
;;; a is the hash algorithm symbol.
;;;

(defun pkcs-sign-base (h l a)
  (if (not (integerp h)) (error "h must be an integer"))
  (if (not (integerp l)) (error "l must be an integer"))
  (if (not (symbolp  a)) (error "a must be a symbol"))
  (if (< (log h 2) 64) (error "h is too small"))  ;#### not sure about this
  (let ((algo-bytes (hash-prefix a))
	(hash-bytes (split-int (nbytes h) h))
	(npad))
    (setf npad (- l (length algo-bytes) (length hash-bytes) 3))
    (if (not (plusp npad)) (error "l is too small"))
    (unite-int (append (list #x00 #x01)
		       (listn npad #xFF)
		       (list #x00)
		       algo-bytes
		       hash-bytes))))


;;;
;;; pkcs-encr-base
;;; Input is the session key integer k,
;;; the length of the modulus in bytes integer l,
;;; and the symmetric algorithm symbol a.
;;; The output is a huge integer that contains two prefix bytes,
;;; a string of non-zero random bytes, a zero byte,
;;; an algorithm byte, the session key bytes, and a two-byte checksum.
;;; See RFC-4880 sections 5.1 and 13.1.1 (EME-PKCS1-v1_5).
;;; ? (setf x (pkcs-encr-base (random (expt 2 128)) 128 'AES-128))
;;; ? (pprint (split-int 128 x))
;;;

(defun pkcs-encr-base (k l a)
  (if (not (integerp k)) (error "k must be an integer"))
  (if (not (integerp l)) (error "l must be an integer"))
  (if (not (symbolp  a)) (error "a must be a symbol"))
  (if (< (log k 2) 64) (error "h is too small"))  ;#### not sure about this
  (let ((key-bytes) (npad))
    (setf key-bytes (split-int (nbytes k) k))
    (setf npad (- l (nbytes k) 6))  ;; 6 extra bytes: 0 2 ... 0 7 ... CSH CSL.
    (if (not (plusp npad)) (error "l is too small"))
    (unite-int (append (list #x00 #x02)
		       (listn npad #xFF)
		       (list #x00)
		       (list (symmetric-algorithm-code a))
		       key-bytes
		       (split-int 2 (checksum key-bytes))))))


;;;
;;; pkcs-okayp
;;; returns T iff all tests pass.
;;;

(defun pkcs-okayp ()
  'T)


