;;;; BlackLight/OpenPGP/packet-CB.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; CB is the first byte in a LITERAL-DATA-PACKET.
;;;; This file contains Lisp code that implements three functions:
;;;; build-packet-CB-body takes a CB field list and returns a CB byte list.
;;;; parse-packet-CB-body takes a CB byte list and returns a CB field list.
;;;; packet-CB-okayp tests build-packet-CB-body and parse-packet-CB-body.
;;;; 
;;;; CB field list:
;;;; 0: LITERAL-DATA-PACKET
;;;; 1: header symbol
;;;; 2: data-type symbol, specifes the type of data in ltrl-data.
;;;; 3: fname-str string, usually specifies a filename.
;;;; 4: file-time string, indicates the date and time the file was created.
;;;; 5: ltrl-data list, 8-bit integers that repesents the literal data.
;;;; 


;;;
;;; build-packet-CB-body
;;; given a list of field values (data-type fname-str file-time ltrl-data),
;;; returns a list of byte values that comprise the body of a CB-packet.
;;;

(defun build-packet-CB-body (p)
  (if (not (listp p)) (error "p must be a list."))
  (if (not (symbolp (nth 0 p))) (error "data-type must be a symbol."))
  (if (not (stringp (nth 1 p))) (error "fname-str must be a string."))
  (if (not (stringp (nth 2 p))) (error "file-time must be an string."))
  (if (not (listp (nth 3 p))) (error "ltrl-data must be a list."))
  (let ((y))
    (setf y (list (data-type-code (nth 0 p))))
    (setf y (append y (list (length (nth 1 p)))))
    (setf y (append y (split-str (nth 1 p))))
    (setf y (append y (split-int 4 (encode-epoch1970-secs (nth 2 p)))))
    (setf y (append y (nth 3 p)))))


;;;
;;; parse-packet-CB-body
;;; given a list m of byte values that comprise the body of a CB-packet,
;;; returns a list of field values (data-type fname-str file-time ltrl-data).
;;;

(defun parse-packet-CB-body (m)
  (if (not (listp m)) (error "m must be a list."))
  (let ((data-type) (fname-len) (fname-str) (file-time) (ltrl-data))
    (setf data-type (data-type-symbol (nth 0 m)))
    (setf fname-len (nth 1 m))
    (setf fname-str (unite-str (subseq m 2 (+ 2 fname-len))))
    (setf file-time (decode-epoch1970-secs (unite-int (subseq m (+ 2 fname-len) (+ 6 fname-len)))))
    (setf ltrl-data (subseq m (+ 6 fname-len) (length m)))
    (list data-type fname-str file-time ltrl-data)))


;;;
;;; literal-data-packet-p
;;; returns T iff p is a literal-data-packet.
;;; 0: LITERAL-DATA-PACKET
;;; 1: header symbol
;;; 2: data-type symbol, specifes the type of data in ltrl-data.
;;; 3: fname-str string, usually specifies a filename.
;;; 4: file-time string, indicates the date and time the file was created.
;;; 5: ltrl-data list, 8-bit integers that repesents the literal data.
;;;

(defun literal-data-packet-p (p)
  (and (listp p)
       (= 6 (length p))
       (symbolp (nth 0 p))
       (equal 'LITERAL-DATA-PACKET (nth 0 p))
       (symbolp (nth 1 p))
       (symbolp (nth 2 p))
       (equal 'BINARY-DATA (nth 2 p))
       (stringp (nth 3 p))
       (> (length (nth 3 p)) 0)
       (time-stringp (nth 4 p))
       (blistp (nth 5 p))))


;;;
;;; packet-CB-okayp
;;; tests the build-packet-CB-body and parse-packet-CB-body function.
;;;

(defun packet-CB-okayp ()
  (let ((x) (y) (z))
    (setf x (list 'BINARY-DATA "sargo.com" (date) (random-bytes 40)))
    (setf y (build-packet-CB-body x))
    (setf z (parse-packet-CB-body y))
    (equal x z)))


