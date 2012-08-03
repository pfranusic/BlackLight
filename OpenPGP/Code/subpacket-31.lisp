;;;; BlackLight/OpenPGP/subpacket-31.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; SIGNATURE-TARGET subpacket (31)
;;;; See RFC-4880 section 5.2.3.25 "Signature Target"
;;;;
;;;;   (1 octet public-key algorithm, 1 octet hash algorithm, N octets hash)
;;;;
;;;;   This subpacket identifies a specific target signature to which a
;;;;   signature refers.  For revocation signatures, this subpacket
;;;;   provides explicit designation of which signature is being revoked.
;;;;   For a third-party or timestamp signature, this designates what
;;;;   signature is signed.  All arguments are an identifier of that target
;;;;   signature.
;;;;
;;;;   The N octets of hash data MUST be the size of the hash of the
;;;;   signature.  For example, a target signature with a SHA-1 hash MUST
;;;;   have 20 octets of hash data.
;;;;


;;;
;;; parse-subpacket-31-body
;;; Input is a list of bytes.
;;; Output is a list with two symbols and an integer.
;;; ? (parse-subpacket-31-body '(3 2 213 218 114 57 119 175 104 83 67 50 183 150 62 106 125 230 109 192 248 203))
;;; (RSA-SIGN-ONLY SHA-1 1220886546994537529084106226173099472021253847243)
;;;

(defun parse-subpacket-31-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (list (public-key-algorithm-symbol (nth 0 b))
	(hash-algorithm-symbol (nth 1 b))
	(unite-int (subseq b 2 (length b)))))


;;;
;;; build-subpacket-31-body
;;; Input is a list with two symbols and an integer.
;;; Output is a list of bytes.
;;; ? (build-subpacket-31-body '(RSA-SIGN-ONLY SHA-1 1220886546994537529084106226173099472021253847243))
;;; (3 2 213 218 114 57 119 175 104 83 67 50 183 150 62 106 125 230 109 192 248 203)
;;;

(defun build-subpacket-31-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 3 (length f)) (error "list f must have three elements"))
  (append (list (public-key-algorithm-code (nth 0 f)))
	  (list (hash-algorithm-code (nth 1 f)))
	  (split-int (nbytes (nth 2 f)) (nth 2 f))))


;;;
;;; subpacket-31-okayp
;;; tests parse-subpacket-31-body and build-subpacket-31-body.
;;;

(defun subpacket-31-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random-public-key-algorithm-symbol)
		  (random-hash-algorithm-symbol)
		  (random (expt 2 160))))
    (setf y (build-subpacket-31-body x))
    (setf z (parse-subpacket-31-body y))
    (equal x z)))


