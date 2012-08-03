;;;; BlackLight/OpenPGP/subpacket-11.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; PREFERRED-SYMMETRIC-ALGORITHMS subpacket (11)
;;;; See RFC-4880 section 5.2.3.7 "Preferred Symmetric Algorithms"
;;;;
;;;;   (array of one-octet values)
;;;;
;;;;   Symmetric algorithm numbers that indicate which algorithms the key
;;;;   holder prefers to use.  The subpacket body is an ordered list of
;;;;   octets with the most preferred listed first.  It is assumed that only
;;;;   algorithms listed are supported by the recipient's software.
;;;;   Algorithm numbers are in Section 9.  This is only found on a self-
;;;;   signature.
;;;;


;;;
;;; parse-subpacket-11-body
;;; Input is a list of m bytes.
;;; Output is a list of m symbols.
;;; ? (parse-subpacket-11-body '(7 8 9))
;;; (AES-128 AES-192 AES-256)
;;;

(defun parse-subpacket-11-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (mapcar #'symmetric-algorithm-symbol b))


;;;
;;; build-subpacket-11-body
;;; Input is a list of m symbols.
;;; Output is a list of m bytes.
;;; ? (build-subpacket-11-body '(AES-128 AES-192 AES-256))
;;; (7 8 9)
;;;

(defun build-subpacket-11-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (mapcar #'symmetric-algorithm-code f))


;;;
;;; subpacket-11-okayp
;;; tests parse-subpacket-11-body and build-subpacket-11-body.
;;;

(defun subpacket-11-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random 11) (random 11) (+ 100 (random 11))))
    (setf y (parse-subpacket-11-body x))
    (setf z (build-subpacket-11-body y))
    (equal x z)))


