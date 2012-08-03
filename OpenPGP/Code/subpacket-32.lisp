;;;; BlackLight/OpenPGP/subpacket-32.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; EMBEDDED-SIGNATURE subpacket (32)
;;;; See RFC-4880 section 5.2.3.26 "Embedded Signature"
;;;;
;;;;   (1 signature packet body)
;;;;
;;;;   This subpacket contains a complete Signature packet body as
;;;;   specified in Section 5.2 above.  It is useful when one signature
;;;;   needs to refer to, or be incorporated in, another signature.
;;;;


;;;
;;; parse-subpacket-32-body
;;;

(defun parse-subpacket-32-body (b)
  (parse-packet-C2-body b))


;;;
;;; build-subpacket-32-body
;;;

(defun build-subpacket-32-body (f)
  (build-packet-C2-body f))


;;;
;;; subpacket-32-okayp
;;; tests parse-subpacket-32-body and build-subpacket-32-body.
;;;

(defun subpacket-32-okayp ()
  (let ((x) (y) (z))
    (setf x '(VERSION-4
	      PRIMARY-KEY-BINDING-SIGNATURE
	      RSA-ENCR-SIGN
	      SHA-1
	      ((SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC"))
	      ((SUBPACKET-A ISSUER "DE85CA0B6039F25B"))
	      "D7C6"
	      108137120535774604878231133600652542842776122844180327983345575658791429906508473263193157572385247969945564167764348172407072123278432509110534504263620732938025848317547156702724469817734463543585371085980591678712046140490964795559387397969659867224209330153372757230632481867088257971347629209901320408451))
    (setf y (build-subpacket-32-body x))
    (setf z (parse-subpacket-32-body y))
    (equal x z)))


