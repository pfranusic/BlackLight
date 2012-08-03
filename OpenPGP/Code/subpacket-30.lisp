;;;; BlackLight/OpenPGP/subpacket-30.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; FEATURES subpacket (30)
;;;; See RFC-4880 section 5.2.3.24 "Features"
;;;;
;;;;   (N octets of flags)
;;;;
;;;;   The Features subpacket denotes which advanced OpenPGP features a
;;;;   user's implementation supports.  This is so that as features are
;;;;   added to OpenPGP that cannot be backwards-compatible, a user can
;;;;   state that they can use that feature.  The flags are single bits that
;;;;   indicate that a given feature is supported.
;;;;
;;;;   This subpacket is similar to a preferences subpacket, and only
;;;;   appears in a self-signature.
;;;;
;;;;   An implementation SHOULD NOT use a feature listed when sending to a
;;;;   user who does not state that they can use it.
;;;;
;;;;   Defined features are as follows:
;;;;
;;;;       First octet:
;;;;
;;;;       0x01 - Modification Detection (packets 18 and 19)
;;;;
;;;;   If an implementation implements any of the defined features, it
;;;;   SHOULD implement the Features subpacket, too.
;;;;
;;;;   An implementation may freely infer features from other suitable
;;;;   implementation-dependent mechanisms.
;;;;


;;;
;;; parse-subpacket-30-body
;;; Input is a list of m bytes.
;;; Output is a list of m binary strings.
;;; ? (parse-subpacket-30-body '(5 31 14))
;;; ("101" "11111" "1110")
;;;

(defun parse-subpacket-30-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (mapcar #'int-bin b))


;;;
;;; build-subpacket-30-body
;;; Input is a list of m binary strings.
;;; Output is a list of m bytes.
;;; ? (build-subpacket-30-body '("101" "11111" "1110"))
;;; (5 31 14)
;;;

(defun build-subpacket-30-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (mapcar #'bin-int f))


;;;
;;; subpacket-30-okayp
;;; tests parse-subpacket-30-body and build-subpacket-30-body.
;;;

(defun subpacket-30-okayp ()
  (let ((x) (y) (z))
    (setf x (random-bytes 4))
    (setf y (parse-subpacket-30-body x))
    (setf z (build-subpacket-30-body y))
    (equal x z)))


