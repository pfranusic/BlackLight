;;;; BlackLight/OpenPGP/subpacket-22.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; PREFERRED-COMPRESSION-ALGORITHMS subpacket (22)
;;;; See RFC-4880 section 5.2.3.9 "Preferred Compression Algorithms"
;;;;
;;;;   (array of one-octet values)
;;;;
;;;;   Compression algorithm numbers that indicate which algorithms the key
;;;;   holder prefers to use.  Like the preferred symmetric algorithms, the
;;;;   list is ordered.  Algorithm numbers are in Section 9.  If this
;;;;   subpacket is not included, ZIP is preferred.  A zero denotes that
;;;;   uncompressed data is preferred; the key holder's software might have
;;;;   no compression software in that implementation.  This is only found
;;;;   on a self-signature.
;;;;


;;;
;;; parse-subpacket-22-body
;;; Input is a list of m bytes.
;;; Output is a list of m symbols.
;;; ? (parse-subpacket-22-body '(1 2 3))
;;; (ZIP ZLIB BZIP2)
;;;

(defun parse-subpacket-22-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (mapcar #'compression-algorithm-symbol b))


;;;
;;; build-subpacket-22-body
;;; Input is a list of m symbols.
;;; Output is a list of m bytes.
;;; ? (build-subpacket-22-body '(ZIP ZLIB BZIP2))
;;; (1 2 3)
;;;

(defun build-subpacket-22-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (mapcar #'compression-algorithm-code f))


;;;
;;; subpacket-22-okayp
;;; tests parse-subpacket-22-body and build-subpacket-22-body.
;;;

(defun subpacket-22-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random 4) (+ 100 (random 11))))
    (setf y (parse-subpacket-22-body x))
    (setf z (build-subpacket-22-body y))
    (equal x z)))


