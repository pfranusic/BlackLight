;;;; BlackLight/OpenPGP/sym-algs.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; See RFC-4880 section 9.2
;;;;
;;;;   Implementations MUST implement TripleDES.  Implementations SHOULD
;;;;   implement AES-128 and CAST5.  Implementations that interoperate with
;;;;   PGP 2.6 or earlier need to support IDEA, as that is the only
;;;;   symmetric cipher those versions use.  Implementations MAY implement
;;;;   any other algorithm.
;;;;


;;;
;;; symmetric-algorithms
;;;

(defconstant symmetric-algorithms
  '((0                PLAINTEXT)
    (1                     IDEA)
    (2               TRIPLE-DES)
    (3                    CAST5)
    (4                 BLOWFISH)
    (5               RESERVED-5)
    (6               RESERVED-6)
    (7                  AES-128)
    (8                  AES-192)
    (9                  AES-256)
    (10             TWOFISH-256)
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
;;; random-symmetric-algorithm-symbol
;;; This is used for testing purposes.
;;;

(defun random-symmetric-algorithm-symbol ()
  (nth 1 (nth (random (length symmetric-algorithms))
	      symmetric-algorithms)))


;;;
;;; random-symmetric-algorithm-code
;;; This is used for testing purposes.
;;;

(defun random-symmetric-algorithm-code ()
  (nth 0 (nth (random (length symmetric-algorithms))
	      symmetric-algorithms)))


;;;
;;; symmetric-algorithm-symbol
;;; Input is an integer representation.
;;; Output is a symbol representation.
;;;

(defun symmetric-algorithm-symbol (n)
  (if (not (integerp n))
      (error "n must be an integer"))
  (dotimes (i (length symmetric-algorithms))
    (if (= n (nth 0 (nth i symmetric-algorithms)))
	(return-from symmetric-algorithm-symbol
		     (nth 1 (nth i symmetric-algorithms)))))
  'INVALID)


;;;
;;; symmetric-algorithm-code
;;; Input is a symbol representation.
;;; Output is an integer representation.
;;;

(defun symmetric-algorithm-code (s)
  (if (not (symbolp s))
      (error "s must be a symbol"))
  (dotimes (i (length symmetric-algorithms))
    (if (eq s (nth 1 (nth i symmetric-algorithms)))
	(return-from symmetric-algorithm-code
		     (nth 0 (nth i symmetric-algorithms)))))
  999)


;;;
;;; sym-algs-okayp
;;; tests this module
;;;

(defun sym-algs-okayp ()
  (let ((x) (y) (z))
    (dotimes (i 10)
      (setf x (random-symmetric-algorithm-symbol))
      (setf y (symmetric-algorithm-code x))
      (setf z (symmetric-algorithm-symbol y))
      (if (not (equal x z))
	  (return-from sym-algs-okayp nil)))
    (dotimes (i 10)
      (setf x (random-symmetric-algorithm-code))
      (setf y (symmetric-algorithm-symbol x))
      (setf z (symmetric-algorithm-code y))
      (if (not (equal x z))
	  (return-from sym-algs-okayp nil)))
    T))


