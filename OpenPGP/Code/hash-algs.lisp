;;;; BlackLight/OpenPGP/hash-algs.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; See RFC-4880 section 9.4 "Hash Algorithms"
;;;;
;;;;   Implementations MUST implement SHA-1.
;;;;   Implementations MAY implement other algorithms.
;;;;   MD5 is deprecated.
;;;;


;;;
;;; hash-algorithms
;;;

(defconstant hash-algorithms
  '((1                      MD5)
    (2                    SHA-1)
    (3               RIPEMD-160)
    (4               RESERVED-4)
    (5               RESERVED-5)
    (6               RESERVED-6)
    (7               RESERVED-7)
    (8                  SHA-256)
    (9                  SHA-384)
    (10                 SHA-512)
    (11                 SHA-224)
    (100       EXPERIMENTAL-100)
    (101       EXPERIMENTAL-101)
    (102       EXPERIMENTAL-102)
    (103       EXPERIMENTAL-103)
    (104       EXPERIMENTAL-104)
    (105       EXPERIMENTAL-105)
    (106       EXPERIMENTAL-106)
    (107       EXPERIMENTAL-107)
    (108       EXPERIMENTAL-108)
    (109       EXPERIMENTAL-109)
    (110       EXPERIMENTAL-110)))


;;;
;;; random-hash-algorithm-symbol
;;; This is used for testing purposes.
;;;

(defun random-hash-algorithm-symbol ()
  (nth 1 (nth (random (length hash-algorithms))
	      hash-algorithms)))


;;;
;;; random-hash-algorithm-code
;;; This is used for testing purposes.
;;;

(defun random-hash-algorithm-code ()
  (nth 0 (nth (random (length hash-algorithms))
	      hash-algorithms)))


;;;
;;; hash-algorithm-symbol
;;; Input is an integer representation.
;;; Output is a symbol representation.
;;;

(defun hash-algorithm-symbol (n)
  (if (not (integerp n))
      (error "n must be an integer"))
  (dotimes (i (length hash-algorithms))
    (if (= n (nth 0 (nth i hash-algorithms)))
	(return-from hash-algorithm-symbol
		     (nth 1 (nth i hash-algorithms)))))
  'INVALID)


;;;
;;; hash-algorithm-code
;;; Input is a symbol representation.
;;; Output is an integer representation.
;;;

(defun hash-algorithm-code (s)
  (if (not (symbolp s))
      (error "s must be a symbol"))
  (dotimes (i (length hash-algorithms))
    (if (eq s (nth 1 (nth i hash-algorithms)))
	(return-from hash-algorithm-code
		     (nth 0 (nth i hash-algorithms)))))
  999)


;;;
;;; hash-algs-okayp
;;; tests this module
;;;

(defun hash-algs-okayp ()
  (let ((x) (y) (z))
    (dotimes (i 10)
      (setf x (random-hash-algorithm-symbol))
      (setf y (hash-algorithm-code x))
      (setf z (hash-algorithm-symbol y))
      (if (not (equal x z))
	  (return-from hash-algs-okayp nil)))
    (dotimes (i 10)
      (setf x (random-hash-algorithm-code))
      (setf y (hash-algorithm-symbol x))
      (setf z (hash-algorithm-code y))
      (if (not (equal x z))
	  (return-from hash-algs-okayp nil)))
    T))


