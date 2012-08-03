;;;; BlackLight/OpenPGP/subpacket-04.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; EXPORTABLE-CERTIFICATION subpacket (04)
;;;; See RFC-4880 section 5.2.3.11
;;;;
;;;;   (1 octet of exportability, 0 for not, 1 for exportable)
;;;;
;;;;   This subpacket denotes whether a certification signature is
;;;;   "exportable", to be used by other users than the signature's issuer.
;;;;   The packet body contains a Boolean flag indicating whether the
;;;;   signature is exportable.  If this packet is not present, the
;;;;   certification is exportable; it is equivalent to a flag containing a 1.
;;;;
;;;;   Non-exportable, or "local", certifications are signatures made by a
;;;;   user to mark a key as valid within that user's implementation only.
;;;;   Thus, when an implementation prepares a user's copy of a key for
;;;;   transport to another user (this is the process of "exporting" the
;;;;   key), any local certification signatures are deleted from the key.
;;;;
;;;;   The receiver of a transported key "imports" it, and likewise trims
;;;;   any local certifications.  In normal operation, there won't be any,
;;;;   assuming the import is performed on an exported key.  However, there
;;;;   are instances where this can reasonably happen.  For example, if an
;;;;   implementation allows keys to be imported from a key database in
;;;;   addition to an exported key, then this situation can arise.
;;;;
;;;;   Some implementations do not represent the interest of a single user
;;;;   (for example, a key server).  Such implementations always trim local
;;;;   certifications from any key they handle.
;;;;


;;;
;;; parse-subpacket-04-body
;;; Input is a list of one byte.
;;; Output is a list with one boolean symbol.
;;; ? (parse-subpacket-04-body '(1))
;;; (TRUE)
;;;

(defun parse-subpacket-04-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 1 (length b)) (error "list b must have 1 element"))
  (case (nth 0 b) (1 '(TRUE)) (otherwise '(FALSE))))


;;;
;;; build-subpacket-04-body
;;; Input is a list with one boolean symbol.
;;; Output is a list of one byte.
;;; ? (build-subpacket-04-body '(TRUE))
;;; (1)
;;;

(defun build-subpacket-04-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (case (nth 0 f)
	(TRUE  (list 1))
	(FALSE (list 0))
	(otherwise (error "argument must be TRUE or FALSE"))))


;;;
;;; subpacket-04-okayp
;;; tests parse-subpacket-04-body and build-subpacket-04-body.
;;;

(defun subpacket-04-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random 2)))
    (setf y (parse-subpacket-04-body x))
    (setf z (build-subpacket-04-body y))
    (equal x z)))


