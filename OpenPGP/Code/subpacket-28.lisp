;;;; BlackLight/OpenPGP/subpacket-28.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; SIGNERS-USER-ID subpacket (28)
;;;; See RFC-4880 section 5.2.3.22 "Signer's User ID"
;;;;
;;;;   (String)
;;;;
;;;;   This subpacket allows a keyholder to state which User ID is
;;;;   responsible for the signing.  Many keyholders use a single key for
;;;;   different purposes, such as business communications as well as
;;;;   personal communications.  This subpacket allows such a keyholder to
;;;;   state which of their roles is making a signature.
;;;;
;;;;   This subpacket is not appropriate to use to refer to a User Attribute
;;;;   packet.
;;;;


;;;
;;; parse-subpacket-28-body
;;; Input is a list of bytes.
;;; Output is a string.
;;; ? (parse-subpacket-28-body '(98 111 98 64 117 118 46 111 114 103))
;;; ("bob@uv.org")
;;;

(defun parse-subpacket-28-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (list (unite-str b)))


;;;
;;; build-subpacket-28-body
;;; Input is a string.
;;; Output is a list of bytes.
;;; ? (build-subpacket-28-body '("bob@uv.org"))
;;; (98 111 98 64 117 118 46 111 114 103)
;;;

(defun build-subpacket-28-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have one element"))
  (split-str (nth 0 f)))


;;;
;;; subpacket-28-okayp
;;; tests parse-subpacket-28-body and build-subpacket-28-body.
;;;

(defun subpacket-28-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random-string (+ 10 (random 10)))))
    (setf y (build-subpacket-28-body x))
    (setf z (parse-subpacket-28-body y))
    (equal x z)))


