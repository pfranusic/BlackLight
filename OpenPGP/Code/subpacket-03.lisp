;;;; BlackLight/OpenPGP/subpacket-03.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; SIGNATURE-EXPIRATION-TIME subpacket (03)
;;;; See RFC-4880 section 5.2.3.10
;;;;
;;;;   (4-octet time field)
;;;;
;;;;   The validity period of the signature.  This is the number of seconds
;;;;   after the signature creation time that the signature expires.  If
;;;;   this is not present or has a value of zero, it never expires.
;;;;


;;;
;;; parse-subpacket-03-body
;;; Input is a list of four bytes.
;;; Output is a list with one integer field.
;;; ? (parse-subpacket-03-body '(91 141 120 142))
;;; (1535998094)
;;;

(defun parse-subpacket-03-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 4 (length b)) (error "list b must have 4 elements"))
  (list (unite-int b)))


;;;
;;; build-subpacket-03-body
;;; Input is a list with one integer field.
;;; Output is a list of four bytes.
;;; ? (build-subpacket-03-body '(1535998094))
;;; (91 141 120 142)
;;;

(defun build-subpacket-03-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (split-int 4 (nth 0 f)))


;;;
;;; subpacket-03-okayp
;;; tests parse-subpacket-03-body and build-subpacket-03-body.
;;;

(defun subpacket-03-okayp ()
  (let ((x) (y) (z))
    (setf x (split-int 4 (random (expt 2 27))))
    (setf y (parse-subpacket-03-body x))
    (setf z (build-subpacket-03-body y))
    (equal x z)))


