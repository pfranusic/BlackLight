;;;; BlackLight/OpenPGP/subpacket-21.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; PREFERRED-HASH-ALGORITHMS subpacket (21)
;;;; See RFC-4880 section 5.2.3.8 "Preferred Hash Algorithms"
;;;;
;;;;   (array of one-octet values)
;;;;
;;;;   Message digest algorithm numbers that indicate which algorithms the
;;;;   key holder prefers to receive.  Like the preferred symmetric
;;;;   algorithms, the list is ordered.  Algorithm numbers are in Section 9.
;;;;   This is only found on a self-signature.
;;;;


;;;
;;; parse-subpacket-21-body
;;; Input is a list of m bytes.
;;; Output is a list of m symbols.
;;; ? (parse-subpacket-21-body '(8 10 2))
;;; (SHA-256 SHA-512 SHA-1)
;;;

(defun parse-subpacket-21-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (mapcar #'hash-algorithm-symbol b))


;;;
;;; build-subpacket-21-body
;;; Input is a list of m symbols.
;;; Output is a list of m bytes.
;;; ? (build-subpacket-21-body '(SHA-256 SHA-512 SHA-1))
;;; (8 10 2)
;;;

(defun build-subpacket-21-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (mapcar #'hash-algorithm-code f))


;;;
;;; subpacket-21-okayp
;;; tests parse-subpacket-21-body and build-subpacket-21-body.
;;;

(defun subpacket-21-okayp ()
  (let ((x) (y) (z))
    (setf x (list (1+ (random 11)) (1+ (random 11)) (+ 100 (random 11))))
    (setf y (parse-subpacket-21-body x))
    (setf z (build-subpacket-21-body y))
    (equal x z)))


