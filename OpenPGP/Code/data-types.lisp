;;;; BlackLight/OpenPGP/data-types.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; data-type-symbol and data-type-code functions
;;;;


;;;
;;; data-types
;;;

(defconstant data-types
  (list
   '(#x62 BINARY-DATA)
   '(#x6C LOCAL-DATA)
   '(#x74 TEXT-DATA)
   '(#x75 UTF-DATA)))


;;;
;;; data-type-symbol
;;; given a data-type number,
;;; returns a symbol that represents the data type.
;;;

(defun data-type-symbol (n)
  (if (not (integerp n)) (error "~A is not an integer" n))
  (dotimes (i (length data-types))
    (if (= n (first (nth i data-types)))
	(return-from data-type-symbol (second (nth i data-types)))))
  (error "no data-type-symbol for ~A" n))


;;;
;;; data-type-code
;;; given a symbol that represents a data-type name,
;;; returns the data-type number.
;;;

(defun data-type-code (name)
  (if (not (symbolp name)) (error "data-type must be a symbol."))
  (dotimes (i (length data-types))
    (if (equal name (second (nth i data-types)))
	(return-from data-type-code (first (nth i data-types)))))
  (error "data-type does not exist."))


;;;
;;; data-types-okayp
;;; tests data-type-symbol and data-type-code functions
;;;

(defun data-types-okayp ()
  (let ((x) (y) (z))
    (setf x 'BINARY-DATA)
    (setf y (data-type-code x))
    (setf z (data-type-symbol y))
    (equal x z)))


