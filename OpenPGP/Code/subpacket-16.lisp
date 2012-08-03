;;;; BlackLight/OpenPGP/subpacket-16.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; ISSUER subpacket (16)
;;;; See RFC-4880 section 5.2.3.5
;;;;
;;;;   (8-octet Key ID)
;;;;
;;;;   The OpenPGP Key ID of the key issuing the signature.
;;;;


;;;
;;; parse-subpacket-16-body
;;; Input is a list of 8 bytes.
;;; Output is a list with a hex string.
;;; ? (parse-subpacket-16-body '(245 221 133 122 58 84 127 148))
;;; ("F5DD857A3A547F94")
;;;

(defun parse-subpacket-16-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 8 (length b)) (error "list b must have 8 elements"))
  (list (format nil "~16,'0X" (unite-int b))))


;;;
;;; build-subpacket-16-body
;;; Input is a list with a hex string.
;;; Output is a list of 8 bytes.
;;; ? (build-subpacket-16-body (list "F5DD857A3A547F94"))
;;; (245 221 133 122 58 84 127 148)
;;;

(defun build-subpacket-16-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (split-int 8 (hex-int (nth 0 f))))


;;;
;;; subpacket-16-okayp
;;; tests parse-subpacket-16-body and build-subpacket-16-body.
;;;

(defun subpacket-16-okayp ()
  (let ((x) (y) (z))
    (setf x (random-bytes 8))
    (setf y (parse-subpacket-16-body x))
    (setf z (build-subpacket-16-body y))
    (equal x z)))


