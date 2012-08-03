;;;; BlackLight/OpenPGP/version-types.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; version-type-symbol and version-type-code functions
;;;; 


;;;
;;; version-types
;;;

(defconstant version-types
  (list
   '(1 VERSION-1)
   '(2 VERSION-2)
   '(3 VERSION-3)
   '(4 VERSION-4)))
     

;;;
;;; version-type-symbol
;;; given a version-type integer num,
;;; returns a symbol that represents the version type.
;;;

(defun version-type-symbol (num)
  (if (not (integerp num)) (error "~A is not an integer." num))
  (dotimes (i (length version-types))
    (if (= num (first (nth i version-types)))
	(return-from version-type-symbol (second (nth i version-types)))))
  (error "No version-type-symbol for ~A." num))


;;;
;;; version-type-code
;;; given a name symbol that represents the version type,
;;; returns the version-type number.
;;;

(defun version-type-code (name)
  (if (not (symbolp name)) (error "~A is not a symbol." name))
  (dotimes (i (length version-types))
    (if (equal name (second (nth i version-types)))
	(return-from version-type-code (first (nth i version-types)))))
  (error "No version-type-code for ~A." name))


;;;
;;; version-types-okayp
;;; tests version-type-symbol and version-type-code functions
;;;

(defun version-types-okayp ()
  (let ((x) (y) (z))
    (setf x 'VERSION-4)
    (setf y (version-type-code x))
    (setf z (version-type-symbol y))
    (equal x z)))


