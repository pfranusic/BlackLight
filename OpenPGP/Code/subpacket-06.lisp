;;;; BlackLight/OpenPGP/subpacket-06.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; REGULAR-EXPRESSION subpacket (06)
;;;; See RFC-4880 section 5.2.3.14
;;;;
;;;;   (null-terminated regular expression)
;;;;
;;;;   Used in conjunction with trust Signature packets (of level > 0) to
;;;;   limit the scope of trust that is extended.  Only signatures by the
;;;;   target key on User IDs that match the regular expression in the body
;;;;   of this packet have trust extended by the trust Signature subpacket.
;;;;   The regular expression uses the same syntax as the Henry Spencer's
;;;;   "almost public domain" regular expression [REGEX] package.  A
;;;;   description of the syntax is found in Section 8 below.
;;;;


;;;
;;; parse-subpacket-06-body
;;; Input is a list of bytes.
;;; Output is a list with one string.
;;; ? (parse-subpacket-06-body '(104 101 108 108 111))
;;; ("hello")
;;;

(defun parse-subpacket-06-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (= 1 (length b)) (error "b must not be empty"))
  (list (unite-str b)))


;;;
;;; build-subpacket-06-body
;;; Input is a list with one string.
;;; Output is a list of bytes.
;;; ? (build-subpacket-06-body '("hello"))
;;; (104 101 108 108 111)
;;;

(defun build-subpacket-06-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (split-str (nth 0 f)))


;;;
;;; subpacket-06-okayp
;;; tests parse-subpacket-06-body and build-subpacket-06-body.
;;;

(defun subpacket-06-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random-string (- 40 (random 15)))))
    (setf y (build-subpacket-06-body x))
    (setf z (parse-subpacket-06-body y))
    (equal x z)))


