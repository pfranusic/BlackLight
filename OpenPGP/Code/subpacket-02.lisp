;;;; BlackLight/OpenPGP/subpacket-02.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; SIGNATURE-CREATION-TIME subpacket (02)
;;;; See RFC-4880 section 5.2.3.4
;;;;
;;;;   (4-octet time field)
;;;;
;;;;   The time the signature was made.
;;;;
;;;;   MUST be present in the hashed area.
;;;;


;;;
;;; parse-subpacket-02-body
;;; Input is a list of four bytes.
;;; Output is a list with one string field.
;;; ? (parse-subpacket-02-body '(77 222 182 64))
;;; ("2011-may-26_20:21:20_utc")
;;;

(defun parse-subpacket-02-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (/= 4 (length b)) (error "list b must have 4 elements"))
  (list (decode-epoch1970-secs (unite-int b))))


;;;
;;; build-subpacket-02-body
;;; Input is a list with one string field.
;;; Output is a list of four bytes.
;;; ? (build-subpacket-02-body '("2011-may-26_20:21:20_utc"))
;;; (77 222 182 64)
;;;

(defun build-subpacket-02-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (/= 1 (length f)) (error "list f must have 1 element"))
  (split-int 4 (encode-epoch1970-secs (nth 0 f))))


;;;
;;; subpacket-02-okayp
;;; tests parse-subpacket-02-body and build-subpacket-02-body
;;; using a random value for Epoch 1970 seconds.
;;;

(defun subpacket-02-okayp ()
  (let ((x) (y) (z))
    (setf x (split-int 4 (random (expt 2 32))))
    (setf y (parse-subpacket-02-body x))
    (setf z (build-subpacket-02-body y))
    (equal x z)))


