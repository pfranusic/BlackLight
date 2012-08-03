;;;; BlackLight/OpenPGP/compr-algs.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; See RFC-4880 section 9.3 "Compression Algorithms"
;;;;
;;;;   Implementations MUST implement uncompressed data.
;;;;   Implementations SHOULD implement ZIP.
;;;;   Implementations MAY implement any other algorithm.
;;;;


;;;
;;; compression-algorithms
;;;

(defconstant compression-algorithms
  '((0             UNCOMPRESSED)
    (1                      ZIP)
    (2                     ZLIB)
    (3                    BZIP2)
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
;;; random-compression-algorithm-symbol
;;; This is used for testing purposes.
;;;

(defun random-compression-algorithm-symbol ()
  (nth 1 (nth (random (length compression-algorithms))
	      compression-algorithms)))


;;;
;;; random-compression-algorithm-code
;;; This is used for testing purposes.
;;;

(defun random-compression-algorithm-code ()
  (nth 0 (nth (random (length compression-algorithms))
	      compression-algorithms)))


;;;
;;; compression-algorithm-symbol
;;; Input is an integer representation.
;;; Output is a symbol representation.
;;;

(defun compression-algorithm-symbol (n)
  (if (not (integerp n))
      (error "n must be an integer"))
  (dotimes (i (length compression-algorithms))
    (if (= n (nth 0 (nth i compression-algorithms)))
	(return-from compression-algorithm-symbol
		     (nth 1 (nth i compression-algorithms)))))
  'INVALID)


;;;
;;; compression-algorithm-code
;;; Input is a symbol representation.
;;; Output is an integer representation.
;;;

(defun compression-algorithm-code (s)
  (if (not (symbolp s))
      (error "s must be a symbol"))
  (dotimes (i (length compression-algorithms))
    (if (eq s (nth 1 (nth i compression-algorithms)))
	(return-from compression-algorithm-code
		     (nth 0 (nth i compression-algorithms)))))
  999)


;;;
;;; compr-algs-okayp
;;; tests this module
;;;

(defun compr-algs-okayp ()
  (let ((x) (y) (z))
    (dotimes (i 10)
      (setf x (random-compression-algorithm-symbol))
      (setf y (compression-algorithm-code x))
      (setf z (compression-algorithm-symbol y))
      (if (not (equal x z))
	  (return-from compr-algs-okayp nil)))
    (dotimes (i 10)
      (setf x (random-compression-algorithm-code))
      (setf y (compression-algorithm-symbol x))
      (setf z (compression-algorithm-code y))
      (if (not (equal x z))
	  (return-from compr-algs-okayp nil)))
    T))


