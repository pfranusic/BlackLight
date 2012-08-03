;;;; BlackLight/OpenPGP/subpacket-24.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; PREFERRED-KEY-SERVER subpacket (24)
;;;; See RFC-4880 section 5.2.3.18 "Preferred Key Server"
;;;;
;;;;   (String)
;;;;
;;;;   This is a URI of a key server that the key holder prefers be used for
;;;;   updates.  Note that keys with multiple User IDs can have a preferred
;;;;   key server for each User ID.  Note also that since this is a URI, the
;;;;   key server can actually be a copy of the key retrieved by ftp, http,
;;;;   finger, etc.
;;;;


;;;
;;; parse-subpacket-24-body
;;; Input is a list of bytes.
;;; Output is a string.
;;; ? (parse-subpacket-24-body '(120 121 122 46 99 111 109))
;;; ("xyz.com")
;;;

(defun parse-subpacket-24-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (list (unite-str b)))


;;;
;;; build-subpacket-24-body
;;; Input is a string.
;;; Output is a list of bytes.
;;; ? (build-subpacket-24-body '("xyz.com"))
;;; (120 121 122 46 99 111 109)
;;;

(defun build-subpacket-24-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have one element"))
  (split-str (nth 0 f)))


;;;
;;; subpacket-24-okayp
;;; tests parse-subpacket-24-body and build-subpacket-24-body.
;;;

(defun subpacket-24-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random-string (+ 10 (random 10)))))
    (setf y (build-subpacket-24-body x))
    (setf z (parse-subpacket-24-body y))
    (equal x z)))


