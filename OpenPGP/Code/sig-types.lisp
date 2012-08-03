;;;; BlackLight/OpenPGP/sig-types.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; signature-type-symbol and signature-type-code functions
;;;; 


;;;
;;; signature-types
;;;

(defconstant signature-types
  (list
   '(#x00 BINARY-SIGNATURE)
   '(#x01 TEXT-SIGNATURE)
   '(#x02 STANDALONE-SIGNATURE)
   '(#x10 GENERIC-CERTIFICATION)
   '(#x11 PERSONA-CERTIFICATION)
   '(#x12 CASUAL-CERTIFICATION)
   '(#x13 POSITIVE-CERTIFICATION)
   '(#x18 SUBKEY-BINDING-SIGNATURE)
   '(#x19 PRIMARY-KEY-BINDING-SIGNATURE)
   '(#x1F SIGNATURE-DIRECTLY-ON-KEY)
   '(#x20 KEY-REVOCATION-SIGNATURE)
   '(#x28 SUBKEY-REVOCATION-SIGNATURE)
   '(#x30 CERTIFICATION-REVOCATION-SIGNATURE)
   '(#x40 TIMESTAMP-SIGNATURE)
   '(#x50 THIRD-PARTY-CONFIRMATION-SIGNATURE)))


;;;
;;; signature-type-symbol
;;; given a signet-type integer num,
;;; returns a symbol that represents the signature type.
;;;

(defun signature-type-symbol (num)
  (if (not (integerp num)) (error "~A is not an integer." num))
  (dotimes (i (length signature-types))
    (if (= num (first (nth i signature-types)))
	(return-from signature-type-symbol (second (nth i signature-types)))))
  (error "No signature-type-symbol for ~A." num))


;;;
;;; signature-type-code
;;; given a name symbol that represents the signature type,
;;; returns the signet-type number.
;;;

(defun signature-type-code (name)
  (if (not (symbolp name)) (error "~A is not a symbol." name))
  (dotimes (i (length signature-types))
    (if (equal name (second (nth i signature-types)))
	(return-from signature-type-code (first (nth i signature-types)))))
  (error "No signature-type-code for ~A." name))


;;;
;;; sig-types-okayp
;;; tests signature-type-symbol and signature-type-code functions
;;;

(defun sig-types-okayp ()
  (let ((x) (y) (z))
    (setf x 'BINARY-SIGNATURE)
    (setf y (signature-type-code x))
    (setf z (signature-type-symbol y))
    (equal x z)))


