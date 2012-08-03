;;;; BlackLight/OpenPGP/message.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; build-message and parse-message functions
;;;;


;;;
;;; build-message
;;; takes a nested mssg-fields list and returns a flat mssg-bytes list.
;;;

(defun build-message (mssg-fields)
  (if (not (listp mssg-fields)) (error "mssg-fields is not a list"))
  (let ((packet-fields) (packet-bytes) (mssg-bytes))
    (setf mssg-bytes nil)
    (dotimes (i (length mssg-fields))
      (setf packet-fields (copy-list (nth i mssg-fields)))
      (setf packet-bytes (build-packet packet-fields))
      (dotimes (j (length packet-bytes))
	(push (pop packet-bytes) mssg-bytes)))
    (reverse mssg-bytes)))


;;;
;;; parse-message
;;; Input is a list of bytes.
;;; Output is a list of packets.
;;; ? (parse-message '(5 2 77 163 36 164 2 27 47))
;;; ((SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC")
;;;  (SUBPACKET-A KEY-FLAGS "101111"))
;;; takes a flat mssg-bytes list and returns a nested mssg-fields list.
;;;

(defun parse-message (mssg-bytes)
  (if (not (blistp mssg-bytes)) (error "mssg-bytes must be a list of bytes."))
;;;;  (let ((mssg-fields) (x) (packet-fields) (n))  #### REPLACED BY LINE BELOW
  (let ((mssg-fields) (packet-fields) (n))
    (setf mssg-fields nil)
    (do () ((= (length mssg-bytes) 0) mssg-fields)
	(multiple-value-bind (r0 r1)
			     (parse-packet mssg-bytes)
			     (setf packet-fields r0)
			     (setf n r1))
	(setf mssg-fields (append mssg-fields (list packet-fields)))
	(dotimes (i n) (pop mssg-bytes)))
    mssg-fields))


;;;
;;; message-vectors
;;; is a list of filenames, where each file
;;; contains an OpenPGP message.
;;;

(defconstant message-vectors 
  (list "../Test/Blake.pgp"
	"../Test/quick.pgp"
	"../Test/random.pgp"))


;;;
;;; message-okayp
;;;

(defun message-okayp ()
  (let ((x) (y) (z))
    (dotimes (i (length message-vectors))
      (setf x (getfile (nth i message-vectors)))
      (setf y (parse-message x))
      (setf z (build-message y))
      (if (not (equal x z))
	  (return-from message-okayp NIL))))
  T)


