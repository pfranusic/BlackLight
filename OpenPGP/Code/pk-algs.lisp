;;;; BlackLight/OpenPGP/pk-algs.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; See RFC-4880 section 9.1 "Public-Key Algorithms"
;;;;
;;;;   Implementations MUST implement DSA for signatures, and Elgamal for
;;;;   encryption.  Implementations SHOULD implement RSA keys (1).  RSA
;;;;   Encrypt-Only (2) and RSA Sign-Only are deprecated and SHOULD NOT be
;;;;   generated, but may be interpreted.  See Section 13.5.  See Section
;;;;   13.8 for notes on Elliptic Curve (18), ECDSA (19), Elgamal Encrypt or
;;;;   Sign (20), and X9.42 (21).  Implementations MAY implement any other
;;;;   algorithm.
;;;;


;;;
;;; public-key-algorithms
;;;

(defconstant public-key-algorithms
  '((1            RSA-ENCR-SIGN)
    (2            RSA-ENCR-ONLY)
    (3            RSA-SIGN-ONLY)
    (16                 ELGAMAL)
    (17                     DSA)
    (18          ELLIPTIC-CURVE)
    (19                   ECDSA)
    (20             RESERVED-20)
    (21          DIFFIE-HELLMAN)
    (100           RESERVED-100)
    (101           RESERVED-101)
    (102           RESERVED-102)
    (103           RESERVED-103)
    (104           RESERVED-104)
    (105           RESERVED-105)
    (106           RESERVED-106)
    (107           RESERVED-107)
    (108           RESERVED-108)
    (109           RESERVED-109)
    (110           RESERVED-110)))


;;;
;;; random-public-key-algorithm-symbol
;;; This is used for testing purposes.
;;;

(defun random-public-key-algorithm-symbol ()
  (nth 1 (nth (random (length public-key-algorithms))
	      public-key-algorithms)))


;;;
;;; random-public-key-algorithm-code
;;; This is used for testing purposes.
;;;

(defun random-public-key-algorithm-code ()
  (nth 0 (nth (random (length public-key-algorithms))
	      public-key-algorithms)))


;;;
;;; public-key-algorithm-symbol
;;; Input is an integer representation.
;;; Output is a symbol representation.
;;;

(defun public-key-algorithm-symbol (n)
  (if (not (integerp n))
      (error "n must be an integer"))
  (dotimes (i (length public-key-algorithms))
    (if (= n (nth 0 (nth i public-key-algorithms)))
	(return-from public-key-algorithm-symbol
		     (nth 1 (nth i public-key-algorithms)))))
  'INVALID)


;;;
;;; public-key-algorithm-code
;;; Input is a symbol representation.
;;; Output is an integer representation.
;;;

(defun public-key-algorithm-code (s)
  (if (not (symbolp s))
      (error "s must be a symbol"))
  (dotimes (i (length public-key-algorithms))
    (if (eq s (nth 1 (nth i public-key-algorithms)))
	(return-from public-key-algorithm-code
		     (nth 0 (nth i public-key-algorithms)))))
  999)


;;;
;;; pk-algs-okayp
;;; tests this module
;;;

(defun pk-algs-okayp ()
  (let ((x) (y) (z))
    (dotimes (i 10)
      (setf x (random-public-key-algorithm-symbol))
      (setf y (public-key-algorithm-code x))
      (setf z (public-key-algorithm-symbol y))
      (if (not (equal x z))
	  (return-from pk-algs-okayp nil)))
    (dotimes (i 10)
      (setf x (random-public-key-algorithm-code))
      (setf y (public-key-algorithm-symbol x))
      (setf z (public-key-algorithm-code y))
      (if (not (equal x z))
	  (return-from pk-algs-okayp nil)))
    T))


