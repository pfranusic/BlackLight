;;;; BlackLight/OpenPGP/subpacket-26.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; POLICY-URI subpacket (26)
;;;; See RFC-4880 section 5.2.3.20 "Policy URI"
;;;;
;;;;   (String)
;;;;
;;;;   This subpacket contains a URI of a document that describes
;;;;   the policy under which the signature was issued.
;;;;


;;;
;;; parse-subpacket-26-body
;;; Input is a list of bytes.
;;; Output is a string.
;;; ? (parse-subpacket-26-body '(117 118 46 111 114 103))
;;; ("uv.org")
;;;

(defun parse-subpacket-26-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (list (unite-str b)))


;;;
;;; build-subpacket-26-body
;;; Input is a string.
;;; Output is a list of bytes.
;;; ? (build-subpacket-26-body '("uv.org"))
;;; (117 118 46 111 114 103)
;;;

(defun build-subpacket-26-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have one element"))
  (split-str (nth 0 f)))


;;;
;;; subpacket-26-okayp
;;; tests parse-subpacket-26-body and build-subpacket-26-body.
;;;

(defun subpacket-26-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random-string (+ 10 (random 10)))))
    (setf y (build-subpacket-26-body x))
    (setf z (parse-subpacket-26-body y))
    (equal x z)))


