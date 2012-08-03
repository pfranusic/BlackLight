;;;; BlackLight/OpenPGP/subpacket-25.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; PRIMARY-USER-ID subpacket (25)
;;;; See RFC-4880 section 5.2.3.19 "Primary User ID"
;;;;
;;;;   (1 octet, Boolean)
;;;;
;;;;   This is a flag in a User ID's self-signature that states whether this
;;;;   User ID is the main User ID for this key.  It is reasonable for an
;;;;   implementation to resolve ambiguities in preferences, etc. by
;;;;   referring to the primary User ID.  If this flag is absent, its value
;;;;   is zero.  If more than one User ID in a key is marked as primary, the
;;;;   implementation may resolve the ambiguity in any way it sees fit, but
;;;;   it is RECOMMENDED that priority be given to the User ID with the most
;;;;   recent self-signature.
;;;;
;;;;   When appearing on a self-signature on a User ID packet, this
;;;;   subpacket applies only to User ID packets.  When appearing on a
;;;;   self-signature on a User Attribute packet, this subpacket applies
;;;;   only to User Attribute packets.  That is to say, there are two
;;;;   different and independent "primaries" -- one for User IDs, and one
;;;;   for User Attributes.
;;;;


;;;
;;; parse-subpacket-25-body
;;; Input is a list of one byte.
;;; Output is a list containing the symbol TRUE or FALSE.
;;; ? (parse-subpacket-25-body '(1))
;;; (TRUE)
;;;

(defun parse-subpacket-25-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 1 (length b)) (error "list b must have 1 element"))
  (case (nth 0 b) (1 '(TRUE)) (0 '(FALSE))
	(otherwise (error "boolean element must be 0 or 1"))))


;;;
;;; build-subpacket-25-body
;;; Input is a list containing the symbol TRUE or FALSE.
;;; Output is a list of one byte.
;;; ? (build-subpacket-25-body '(TRUE))
;;; (1)
;;;

(defun build-subpacket-25-body (f)
  (if (not (listp f)) (error "f must be a symbol"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (case (nth 0 f) (TRUE '(1)) (FALSE '(0))
	(otherwise (error "boolean element must be TRUE or FALSE"))))


;;;
;;; subpacket-25-okayp
;;; tests parse-subpacket-25-body and build-subpacket-25-body.
;;;

(defun subpacket-25-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random 2)))
    (setf y (parse-subpacket-25-body x))
    (setf z (build-subpacket-25-body y))
    (equal x z)))


