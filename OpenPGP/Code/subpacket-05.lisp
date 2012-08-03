;;;; BlackLight/OpenPGP/subpacket-05.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; TRUST-SIGNATURE subpacket (05)
;;;; See RFC-4880 section 5.2.3.13
;;;;
;;;;   (1 octet "level" (depth), 1 octet of trust amount)
;;;;
;;;;   Signer asserts that the key is not only valid but also trustworthy at
;;;;   the specified level.  Level 0 has the same meaning as an ordinary
;;;;   validity signature.  Level 1 means that the signed key is asserted to
;;;;   be a valid trusted introducer, with the 2nd octet of the body
;;;;   specifying the degree of trust.  Level 2 means that the signed key is
;;;;   asserted to be trusted to issue level 1 trust signatures, i.e., that
;;;;   it is a "meta introducer".  Generally, a level n trust signature
;;;;   asserts that a key is trusted to issue level n-1 trust signatures.
;;;;   The trust amount is in a range from 0-255, interpreted such that
;;;;   values less than 120 indicate partial trust and values of 120 or
;;;;   greater indicate complete trust.  Implementations SHOULD emit values
;;;;   of 60 for partial trust and 120 for complete trust.
;;;;


;;;
;;; parse-subpacket-05-body
;;; Input is a list with two bytes.
;;; Output is a list with one integer field.
;;; ? (parse-subpacket-05-body '(2 120))
;;; (632)
;;;

(defun parse-subpacket-05-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 2 (length b)) (error "list b must have 2 elements"))
  (list (unite-int b)))


;;;
;;; build-subpacket-05-body
;;; Input is a list with one integer field.
;;; Output is a list with two bytes.
;;; ? (build-subpacket-05-body '(632))
;;; (2 120)
;;;

(defun build-subpacket-05-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (split-int 2 (nth 0 f)))


;;;
;;; subpacket-05-okayp
;;; tests parse-subpacket-05-body and build-subpacket-05-body.
;;;

(defun subpacket-05-okayp ()
  (let ((x) (y) (z))
    (setf x (split-int 2 (random (expt 2 16))))
    (setf y (parse-subpacket-05-body x))
    (setf z (build-subpacket-05-body y))
    (equal x z)))


