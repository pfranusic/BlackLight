;;;; BlackLight/OpenPGP/subpacket-20.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; NOTATION-DATA subpacket (20)
;;;; See RFC-4880 section 5.2.3.16
;;;;
;;;;   (4 octets of flags, 2 octets of name length (M),
;;;;                       2 octets of value length (N),
;;;;                       M octets of name data,
;;;;                       N octets of value data)
;;;;


;;;
;;; parse-subpacket-20-body
;;; Input is a list of bytes.
;;; Output is list with four binary strings and two ASCII strings.
;;; ? (parse-subpacket-20-body '(129 130 131 132 0 4 0 3 97 98 99 100 101 102 103))
;;; ("10000001" "10000010" "10000011" "10000100" "abcd" "efg")
;;;

(defun parse-subpacket-20-body (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (if (< (length b) 8) (error "list b is too short"))
  (let ((name-length (unite-int (subseq b 4 6)))
	(value-length (unite-int (subseq b 6 8))))
    (list (int-bin (nth 0 b))
	  (int-bin (nth 1 b))
	  (int-bin (nth 2 b))
	  (int-bin (nth 3 b))
	  (unite-str (subseq b 8 (+ 8 name-length)))
	  (unite-str (subseq b (+ 8 name-length)
			       (+ 8 name-length value-length))))))


;;;
;;; build-subpacket-20-body
;;; Input is list with four binary strings and two ASCII strings.
;;; Output is a list of bytes.
;;; ? (build-subpacket-20-body '("10000001" "10000010" "10000011" "10000100" "abcd" "efg"))
;;; (129 130 131 132 0 4 0 3 97 98 99 100 101 102 103)
;;;

(defun build-subpacket-20-body (f)
  (if (not (listp f)) (error "f must be a list of bytes"))
  (if (/= 6 (length f)) (error "list f must have six elements"))
  (append (list (bin-int (nth 0 f)))
	  (list (bin-int (nth 1 f)))
	  (list (bin-int (nth 2 f)))
	  (list (bin-int (nth 3 f)))
	  (split-int 2 (length (nth 4 f)))
	  (split-int 2 (length (nth 5 f)))
	  (split-str (nth 4 f))
	  (split-str (nth 5 f))))


;;;
;;; subpacket-20-okayp
;;; tests parse-subpacket-20-body and build-subpacket-20-body.
;;;

(defun subpacket-20-okayp ()
  (let ((x) (y) (z))
    (setf x (list (int-bin (random 256))
		  (int-bin (random 256))
		  (int-bin (random 256))
		  (int-bin (random 256))
		  (random-string (+ 10 (random 10)))
		  (random-string (+ 10 (random 10)))))
    (setf y (build-subpacket-20-body x))
    (setf z (parse-subpacket-20-body y))
    (equal x z)))


