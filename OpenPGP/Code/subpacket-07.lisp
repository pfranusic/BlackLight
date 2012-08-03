;;;; BlackLight/OpenPGP/subpacket-07.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; REVOCABLE subpacket (07)
;;;; See RFC-4880 section 5.2.3.12
;;;;
;;;;   (1 octet of revocability, 0 for not, 1 for revocable)
;;;;
;;;;   Signature's revocability status.  The packet body contains a Boolean
;;;;   flag indicating whether the signature is revocable.  Signatures that
;;;;   are not revocable have any later revocation signatures ignored.  They
;;;;   represent a commitment by the signer that he cannot revoke his
;;;;   signature for the life of his key.  If this packet is not present,
;;;;   the signature is revocable.
;;;;

;;;
;;; parse-subpacket-07-body
;;; Input is a list of one byte.
;;; Output is a list containing the symbol TRUE or FALSE.
;;; ? (parse-subpacket-07-body '(0))
;;; (FALSE)
;;;

(defun parse-subpacket-07-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 1 (length b)) (error "list b must have 1 element"))
  (case (nth 0 b) (1 '(TRUE)) (0 '(FALSE))
	(otherwise (error "boolean element must be 0 or 1"))))


;;;
;;; build-subpacket-07-body
;;; Input is a list containing the symbol TRUE or FALSE.
;;; Output is a list of one byte.
;;; ? (build-subpacket-07-body '(FALSE))
;;; (0)
;;;

(defun build-subpacket-07-body (f)
  (if (not (listp f)) (error "f must be a symbol"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (case (nth 0 f) (TRUE '(1)) (FALSE '(0))
	(otherwise (error "boolean element must be TRUE or FALSE"))))


;;;
;;; subpacket-07-okayp
;;; tests parse-subpacket-07-body and build-subpacket-07-body.
;;;

(defun subpacket-07-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random 2)))
    (setf y (parse-subpacket-07-body x))
    (setf z (build-subpacket-07-body y))
    (equal x z)))


