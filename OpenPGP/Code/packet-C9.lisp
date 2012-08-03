;;;; BlackLight/OpenPGP/packet-C9.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; C9 is the first byte in a SYM-ENCR-DATA-PACKET.
;;;; This file contains Lisp code that implements three functions:
;;;; build-packet-C9-body takes a C9 field list and returns a C9 byte list.
;;;; parse-packet-C9-body takes a C9 byte list and returns a C9 field list.
;;;; packet-C9-okayp tests build-packet-C9-body and parse-packet-C9-body.
;;;; 
;;;; C9 field list
;;;; cipher-text: list, 8-bit integers
;;;;
;;;; C9 byte list
;;;; cipher-text: n bytes
;;;;


;;;
;;; build-packet-C9-body
;;; takes a C9 field list f and returns a C9 byte list.
;;;

(defun build-packet-C9-body (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (not (= 1 (length f))) (error "list f must have 1 element"))
  (if (not (listp (nth 0 f))) (error "cipher-text must be a list"))
  (nth 0 f))


;;;
;;; parse-packet-C9-body
;;; takes a C9 byte list b and returns a C9 field list.
;;;

(defun parse-packet-C9-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (list b))


;;;
;;; sym-encr-data-packet-p
;;; returns T iff p is a sym-encr-data-packet.
;;; 0: SYM-ENCR-DATA-PACKET, symbol
;;; 1: header-type, symbol
;;; 2: cipher-text, list of bytes
;;;

(defun sym-encr-data-packet-p (p)
  (and (listp p)
       (= 3 (length p))
       (symbolp (nth 0 p))
       (symbolp (nth 1 p))
       (blistp (nth 2 p))
       (equal 'SYM-ENCR-DATA-PACKET (nth 0 p))))


;;;
;;; packet-C9-okayp
;;; tests build-packet-C9-body and parse-packet-C9-body
;;;

(defun packet-C9-okayp ()
  (let ((x) (y) (z))
    (setf x (list (random-bytes (+ 95 (random 10)))))
    (setf y (build-packet-C9-body x))
    (setf z (parse-packet-C9-body y))
    (equal x z)))


