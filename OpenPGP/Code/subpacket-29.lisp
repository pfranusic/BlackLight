;;;; BlackLight/OpenPGP/subpacket-29.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; REASON-FOR-REVOCATION subpacket (29)
;;;; See RFC-4880 section 5.2.3.23 "Reason for Revocation"
;;;;
;;;;   (1 octet of revocation code, N octets of reason string)
;;;;
;;;;   This subpacket is used only in key revocation and certification
;;;;   revocation signatures.  It describes the reason why the key or
;;;;   certificate was revoked.
;;;;
;;;;   The first octet contains a machine-readable code that denotes the
;;;;   reason for the revocation:
;;;;
;;;;        0  - No reason specified (key revocations or cert revocations)
;;;;
;;;;        1  - Key is superseded (key revocations)
;;;;
;;;;        2  - Key material has been compromised (key revocations)
;;;;
;;;;        3  - Key is retired and no longer used (key revocations)
;;;;
;;;;        32 - User ID information is no longer valid (cert revocations)
;;;;
;;;;        100-110 - Private Use
;;;;
;;;;   Following the revocation code is a string of octets that gives
;;;;   information about the Reason for Revocation in human-readable form
;;;;   (UTF-8).  The string may be null, that is, of zero length.  The
;;;;   length of the subpacket is the length of the reason string plus one.
;;;;   An implementation SHOULD implement this subpacket, include it in all
;;;;   revocation signatures, and interpret revocations appropriately.
;;;;   There are important semantic differences between the reasons, and
;;;;   there are thus important reasons for revoking signatures.
;;;;
;;;;   If a key has been revoked because of a compromise, all signatures
;;;;   created by that key are suspect.  However, if it was merely
;;;;   superseded or retired, old signatures are still valid.  If the
;;;;   revoked signature is the self-signature for certifying a User ID, a
;;;;   revocation denotes that that user name is no longer in use.  Such a
;;;;   revocation SHOULD include a 0x20 code.
;;;;
;;;;   Note that any signature may be revoked, including a certification on
;;;;   some other person's key.  There are many good reasons for revoking a
;;;;   certification signature, such as the case where the keyholder leaves
;;;;   the employ of a business with an email address.  A revoked
;;;;   certification is no longer a part of validity calculations.
;;;;


;;;
;;; revocation-reasons
;;;

(defconstant revocation-reasons
  '((0      NO-REASON-SPECIFIED)
    (1           KEY-SUPERCEDED)
    (2          KEY-COMPROMISED)
    (3              KEY-RETIRED)
    (32         USER-ID-INVALID)
    (100            PRIVATE-100)
    (101            PRIVATE-101)
    (102            PRIVATE-102)
    (103            PRIVATE-103)
    (104            PRIVATE-104)
    (105            PRIVATE-105)
    (106            PRIVATE-106)
    (107            PRIVATE-107)
    (108            PRIVATE-108)
    (109            PRIVATE-109)
    (110            PRIVATE-110)))


;;;
;;; revocation-reason-symbol
;;; Input is an integer representation.
;;; Output is a symbol representation.
;;; ? ? (revocation-reason-symbol 2)
;;; KEY-COMPROMISED
;;;

(defun revocation-reason-symbol (n)
  (if (not (integerp n)) (error "n must be an integer"))
  (dotimes (i (length revocation-reasons))
    (if (= n (nth 0 (nth i revocation-reasons)))
	(return-from revocation-reason-symbol
		     (nth 1 (nth i revocation-reasons)))))
  'INVALID)


;;;
;;; revocation-reason-code
;;; Input is a symbol representation.
;;; Output is an integer representation.
;;; ? (revocation-reason-code 'KEY-COMPROMISED)
;;; 2
;;;

(defun revocation-reason-code (s)
  (if (not (symbolp s)) (error "s must be a symbol"))
  (dotimes (i (length revocation-reasons))
    (if (eq s (nth 1 (nth i revocation-reasons)))
	(return-from revocation-reason-code
		     (nth 0 (nth i revocation-reasons)))))
  255)


;;;
;;; parse-subpacket-29-body
;;; Input is a list of bytes.
;;; Output is a list containing a symbol and a string.
;;; ? (parse-subpacket-29-body '(1 67 111 110 116 97 99 116 32 98 111 98 64 117 118 46 111 114 103))
;;; (KEY-SUPERCEDED "Contact bob@uv.org")
;;;

(defun parse-subpacket-29-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (append (list (revocation-reason-symbol (nth 0 b)))
	  (list (unite-str (subseq b 1 (length b))))))


;;;
;;; build-subpacket-29-body
;;; Input is a list containing a symbol and a string.
;;; Output is a list of bytes.
;;; ? (build-subpacket-29-body '(KEY-SUPERCEDED "Contact bob@uv.org"))
;;; (1 67 111 110 116 97 99 116 32 98 111 98 64 117 118 46 111 114 103)
;;;

(defun build-subpacket-29-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 2 (length f)) (error "list f must have two elements"))
  (append (list (revocation-reason-code (nth 0 f)))
	  (split-str (nth 1 f))))


;;;
;;; subpacket-29-okayp
;;; tests parse-subpacket-29-body and build-subpacket-29-body.
;;;

(defun subpacket-29-okayp ()
  (let ((x) (y) (z))
    (setf x (list (revocation-reason-symbol (+ 100 (random 11)))
		  (random-string (+ 10 (random 10)))))
    (setf y (build-subpacket-29-body x))
    (setf z (parse-subpacket-29-body y))
    (equal x z)))


