;;;; BlackLight/OpenPGP/packet-CD.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; CD is the first byte in a USER-ID-PACKET.
;;;; This file contains Lisp code that implements three functions:
;;;; build-packet-CD-body takes a CD field list and returns a CD byte list.
;;;; parse-packet-CD-body takes a CD byte list and returns a CD field list.
;;;; packet-CD-okayp tests build-packet-CD-body and parse-packet-CD-body.
;;;; 
;;;; CD field list := (utf-8-str)
;;;; packet-name: symbol, 'PUBLIC-KEY-PACKET
;;;; header-type: symbol, specifies the type of header to be used
;;;; user-id: string, typically an RFC 2822 mail name-addr.
;;;;   Example:
;;;;     'USER-ID-PACKET
;;;;     'NEW-HEADER-3
;;;;     "Zeta"
;;;;


;;;
;;; parse-packet-CD-body
;;; given a flat message list m,
;;; returns a nested parsed packet list p.
;;;

(defun parse-packet-CD-body (m)
  (list (unite-str m)))


;;;
;;; build-packet-CD-body
;;; given a nested parsed packet list p,
;;; returns a flat message list m.
;;;

(defun build-packet-CD-body (p)
  (split-str (nth 0 p)))


;;;
;;; packet-CD-okayp
;;;

(defun packet-CD-okayp ()
  (let ((x) (y) (z))
    (setf x (list "Zeta"))
    (setf y (build-packet-CD-body x))
    (setf z (parse-packet-CD-body y))
    (equal x z)))


