;;;; BlackLight/OpenPGP/subpacket-09.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; KEY-EXPIRATION-TIME subpacket (09)
;;;; See RFC-4880 section 5.2.3.6
;;;;
;;;;   (4-octet time field)
;;;;
;;;;   The validity period of the key.  This is the number of seconds after
;;;;   the key creation time that the key expires.  If this is not present
;;;;   or has a value of zero, the key never expires.  This is found only on
;;;;   a self-signature.
;;;;


;;;
;;; parse-subpacket-09-body
;;; Input is a list of four bytes.
;;; Output is a list with one integer field.
;;; ? (parse-subpacket-09-body '(53 229 216 103))
;;; (904255591)
;;;

(defun parse-subpacket-09-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 4 (length b)) (error "list b must have 4 elements"))
  (list (unite-int b)))


;;;
;;; build-subpacket-09-body
;;; Input is an integer.
;;; Output is a list of four bytes.
;;; ? (build-subpacket-09-body '(904255591))
;;; (53 229 216 103)
;;;

(defun build-subpacket-09-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (split-int 4 (nth 0 f)))


;;;
;;; subpacket-09-okayp
;;; tests parse-subpacket-09-body and build-subpacket-09-body.
;;;

(defun subpacket-09-okayp ()
  (let ((x) (y) (z))
    (setf x (split-int 4 (random (expt 2 27))))
    (setf y (parse-subpacket-03-body x))
    (setf z (build-subpacket-03-body y))
    (equal x z)))


