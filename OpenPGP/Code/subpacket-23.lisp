;;;; BlackLight/OpenPGP/subpacket-23.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; KEY-SERVER-PREFERENCES subpacket (23)
;;;; See RFC-4880 section 5.2.3.17 "Key Server Preferences"
;;;;
;;;; (N octets of flags)
;;;;
;;;; This is a list of one-bit flags that indicate preferences that
;;;; the key holder has about how the key is handled on a key server.
;;;; All undefined flags MUST be zero.
;;;;
;;;; First octet: 0x80 = No-modify
;;;; The key holder requests that this key only be modified or
;;;; updated by the key holder or an administrator of the key server.
;;;;
;;;; This is found only on a self-signature.
;;;;


;;;
;;; parse-subpacket-23-body
;;; Input is a list of m bytes.
;;; Output is a list of m binary strings.
;;; ? (parse-subpacket-23-body '(129 130 132))
;;; ("10000001" "10000010" "10000100")
;;;

(defun parse-subpacket-23-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (mapcar #'int-bin b))


;;;
;;; build-subpacket-23-body
;;; Input is a list of m binary strings.
;;; Output is a list of m bytes.
;;; ? (build-subpacket-23-body '("10000001" "10000010" "10000100"))
;;; (129 130 132)
;;;

(defun build-subpacket-23-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (mapcar #'bin-int f))


;;;
;;; subpacket-23-okayp
;;; tests parse-subpacket-23-body and build-subpacket-23-body.
;;;

(defun subpacket-23-okayp ()
  (let ((x) (y) (z))
    (setf x (random-bytes 4))
    (setf y (parse-subpacket-23-body x))
    (setf z (build-subpacket-23-body y))
    (equal x z)))


