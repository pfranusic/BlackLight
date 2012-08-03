;;;; BlackLight/OpenPGP/subpacket-12.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; REVOCATION-KEY subpacket (12)
;;;; See RFC-4880 section 5.2.3.15
;;;;
;;;;   (1 octet of class, 1 octet of public-key algorithm ID, 20 octets of
;;;;   fingerprint)
;;;;
;;;;   Authorizes the specified key to issue revocation signatures for this
;;;;   key.  Class octet must have bit 0x80 set.  If the bit 0x40 is set,
;;;;   then this means that the revocation information is sensitive.  Other
;;;;   bits are for future expansion to other kinds of authorizations.  This
;;;;   is found on a self-signature.
;;;;
;;;;   If the "sensitive" flag is set, the keyholder feels this subpacket
;;;;   contains private trust information that describes a real-world
;;;;   sensitive relationship.  If this flag is set, implementations SHOULD
;;;;   NOT export this signature to other users except in cases where the
;;;;   data needs to be available: when the signature is being sent to the
;;;;   designated revoker, or when it is accompanied by a revocation
;;;;   signature from that revoker.  Note that it may be appropriate to
;;;;   isolate this subpacket within a separate signature so that it is not
;;;;   combined with other subpackets that need to be exported.
;;;;


;;;
;;; parse-subpacket-12-body
;;; Input is a list of twenty-two bytes.
;;; Output is a list with an 8-bit binary string, 
;;; a symmetric algorithm symbol, and an 160-bit integer.
;;; ? (parse-subpacket-12-body '(192 2 97 126 42 33 0 102 225 24 176 182 156 60 255 184 229 55 218 222 186 3))
;;; ("11000000" RSA-ENCR-ONLY 556585668610788714465674307572327855684623186435)
;;;

(defun parse-subpacket-12-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 22 (length b)) (error "list b must have 22 elements"))
  (list (int-bin (nth 0 b))
	(public-key-algorithm-symbol (nth 1 b))
	(unite-int (subseq b 2 22))))


;;;
;;; build-subpacket-12-body
;;; Input is a list with an 8-bit binary string, 
;;; a symmetric algorithm symbol, and an 160-bit integer.
;;; Output is a list of twenty-two bytes.
;;; ? (build-subpacket-12-body '("11000000" RSA-ENCR-ONLY 556585668610788714465674307572327855684623186435))
;;; (192 2 97 126 42 33 0 102 225 24 176 182 156 60 255 184 229 55 218 222 186 3)
;;;

(defun build-subpacket-12-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 3 (length f)) (error "list f must have 3 elements"))
  (append (list (bin-int (nth 0 f)))
	  (list (public-key-algorithm-code (nth 1 f)))
	  (split-int 20 (nth 2 f))))


;;;
;;; subpacket-12-okayp
;;; tests parse-subpacket-12-body and build-subpacket-12-body.
;;;

(defun subpacket-12-okayp ()
  (let ((x) (y) (z))
    (setf x (append (list (random 256) (+ 1 (random 3))) (random-bytes 20)))
    (setf y (parse-subpacket-12-body x))
    (setf z (build-subpacket-12-body y))
    (equal x z)))


