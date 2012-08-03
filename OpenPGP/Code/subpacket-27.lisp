;;;; BlackLight/OpenPGP/subpacket-27.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; KEY-FLAGS subpacket (27)
;;;; See RFC-4880 section 5.2.3.21 "Key Flags"
;;;;
;;;;   (N octets of flags)
;;;;
;;;;   This subpacket contains a list of binary flags that hold information
;;;;   about a key.  It is a string of octets, and an implementation MUST
;;;;   NOT assume a fixed size.  This is so it can grow over time.  If a
;;;;   list is shorter than an implementation expects, the unstated flags
;;;;   are considered to be zero.  The defined flags are as follows:
;;;;
;;;;       First octet:
;;;;
;;;;       0x01 - This key may be used to certify other keys.
;;;;
;;;;       0x02 - This key may be used to sign data.
;;;;
;;;;       0x04 - This key may be used to encrypt communications.
;;;;
;;;;       0x08 - This key may be used to encrypt storage.
;;;;
;;;;       0x10 - The private component of this key may have been split
;;;;              by a secret-sharing mechanism.
;;;;
;;;;       0x20 - This key may be used for authentication.
;;;;
;;;;       0x80 - The private component of this key may be in the
;;;;              possession of more than one person.
;;;;
;;;;   Usage notes:
;;;;
;;;;   The flags in this packet may appear in self-signatures or in
;;;;   certification signatures.  They mean different things depending on
;;;;   who is making the statement -- for example, a certification signature
;;;;   that has the "sign data" flag is stating that the certification is
;;;;   for that use.  On the other hand, the "communications encryption"
;;;;   flag in a self-signature is stating a preference that a given key be
;;;;   used for communications.  Note however, that it is a thorny issue to
;;;;   determine what is "communications" and what is "storage".  This
;;;;   decision is left wholly up to the implementation; the authors of this
;;;;   document do not claim any special wisdom on the issue and realize
;;;;   that accepted opinion may change.
;;;;
;;;;   The "split key" (0x10) and "group key" (0x80) flags are placed on a
;;;;   self-signature only; they are meaningless on a certification
;;;;   signature.  They SHOULD be placed only on a direct-key signature
;;;;   (type 0x1F) or a subkey signature (type 0x18), one that refers to the
;;;;   key the flag applies to.
;;;;


;;;
;;; parse-subpacket-27-body
;;; Input is a list of m bytes.
;;; Output is a list of m binary strings.
;;; ? (parse-subpacket-27-body '(31 5 14))
;;; ("11111" "101" "1110")
;;;

(defun parse-subpacket-27-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (mapcar #'int-bin b))


;;;
;;; build-subpacket-27-body
;;; Input is a list of m binary strings.
;;; Output is a list of m bytes.
;;; ? (build-subpacket-27-body '("11111" "101" "1110"))
;;; (31 5 14)
;;;

(defun build-subpacket-27-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (mapcar #'bin-int f))


;;;
;;; subpacket-27-okayp
;;; tests parse-subpacket-27-body and build-subpacket-27-body.
;;;

(defun subpacket-27-okayp ()
  (let ((x) (y) (z))
    (setf x (random-bytes 4))
    (setf y (parse-subpacket-27-body x))
    (setf z (build-subpacket-27-body y))
    (equal x z)))


