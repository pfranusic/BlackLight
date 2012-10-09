;;;; BlackLight/OpenPGP/aes.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; This file contains Common Lisp expressions that implement 
;;;; the Advanced Encryption Standard (AES) specified in FIPS 197.
;;;; "The AES algorithm is a symmetric block cipher that can 
;;;; encrypt (encipher) and decrypt (decipher) information."
;;;;


;;;
;;; heap data
;;;

(defparameter *aes-128-expand-xw* nil)
(defparameter *aes-128-expand-xk* nil)
(defparameter *aes-128-cfbe-c1* nil)
(defparameter *aes-128-cfbe-p1* nil)
(defparameter *aes-128-cfbe-c0* nil)
(defparameter *aes-128-cfbd-p1* nil)
(defparameter *aes-128-cfbd-c1* nil)
(defparameter *aes-128-cfbd-c0* nil)


;;;
;;; heap pointers
;;;

(defparameter *aes-128-expand-xw-ptr* nil)
(defparameter *aes-128-expand-xk-ptr* nil)
(defparameter *aes-128-cfbe-c1-ptr* nil)
(defparameter *aes-128-cfbe-p1-ptr* nil)
(defparameter *aes-128-cfbe-c0-ptr* nil)
(defparameter *aes-128-cfbd-p1-ptr* nil)
(defparameter *aes-128-cfbd-c1-ptr* nil)
(defparameter *aes-128-cfbd-c0-ptr* nil)


;;;
;;; aes-reset
;;; Opens the shared library aes.dylib, allocates memory
;;; for the schedule and various registers, and evaluates to T.
;;;

(defun aes-reset ()
  (open-shared-library "../AES/aes.dylib")
  (multiple-value-bind (nv np)
    (make-heap-ivector 44 '(unsigned-byte 32))
    (setq *aes-128-expand-xw* nv)
    (setq *aes-128-expand-xw-ptr* np))
  (multiple-value-bind (nv np)
    (make-heap-ivector 16 '(unsigned-byte 8))
    (setq *aes-128-expand-xk* nv)
    (setq *aes-128-expand-xk-ptr* np))
  (multiple-value-bind (nv np)
    (make-heap-ivector 16 '(unsigned-byte 8))
    (setq *aes-128-cfbe-c1* nv)
    (setq *aes-128-cfbe-c1-ptr* np))
  (multiple-value-bind (nv np)
    (make-heap-ivector 16 '(unsigned-byte 8))
    (setq *aes-128-cfbe-p1* nv)
    (setq *aes-128-cfbe-p1-ptr* np))
  (multiple-value-bind (nv np)
    (make-heap-ivector 16 '(unsigned-byte 8))
    (setq *aes-128-cfbe-c0* nv)
    (setq *aes-128-cfbe-c0-ptr* np))
  (multiple-value-bind (nv np)
    (make-heap-ivector 16 '(unsigned-byte 8))
    (setq *aes-128-cfbd-p1* nv)
    (setq *aes-128-cfbd-p1-ptr* np))
  (multiple-value-bind (nv np)
    (make-heap-ivector 16 '(unsigned-byte 8))
    (setq *aes-128-cfbd-c1* nv)
    (setq *aes-128-cfbd-c1-ptr* np))
  (multiple-value-bind (nv np)
    (make-heap-ivector 16 '(unsigned-byte 8))
    (setq *aes-128-cfbd-c0* nv)
    (setq *aes-128-cfbd-c0-ptr* np))
  t)


;;;
;;; aes-128-expand
;;; This is a Lisp wrapper for the C function.
;;; and part of the aes.dylib dynamic library.
;;; Input k is a 128-bit unsigned integer.
;;; Evaluates to w, a 44-element array of 32-bit unsigned integers.
;;;

(defun aes-128-expand (k)
  ;; Make sure that k is an integer in [0,2^128).
  (if (not (and (integerp k) (plusp k) (< (log k 2) 128)))
      (error "k must be an integer less than 2^128"))
  ;; Declare local variables.
  (let ((k-list) (err))
    ;; Copy k to *aes-128-expand-k*.
    (setf k-list (split-int 16 k))
    (dotimes (i 16)
      (setf (aref *aes-128-expand-xk* i) (pop k-list)))
    ;; Call int aes_128_expand (huge xk, huge xw);
    (setf err (external-call "_aes_128_expand"
			     :address *aes-128-expand-xk-ptr*
			     :address *aes-128-expand-xw-ptr*
			     :unsigned-int))
    ;; Check for errors.
    (if (not (= 0 err)) (error "_aes_128_expand returned ~A" err))
    ;; Evaluate the schedule.
    *aes-128-expand-xw*))
    


;;;
;;; aes-128-inite
;;; Initializes the c0 register in the encoder.
;;;

(defun aes-128-inite (x)
  (dotimes (i 16)
    (setf (aref *aes-128-cfbe-c0* i) (pop x))))
  

;;;
;;; aes-128-initd
;;; Initializes the c0 register in the decoder.
;;;

(defun aes-128-initd (x)
  (dotimes (i 16)
    (setf (aref *aes-128-cfbd-c0* i) (pop x))))


;;;
;;; aes-128-cipher
;;; This is a Lisp wrapper for the C function.
;;; Input p1 is a 16-element list of 8-bit unsigned integers.
;;; Evaluates to c1, a 16-element list of 8-bit unsigned integers.
;;;

(defun aes-128-cipher (p1)
  ;; Check validity of p1.
  (if (not (and (blistp p1) (= 16 (length p1))))
      (error "p1 must be a list of 16 bytes"))
  ;; Declare local variables.
  (let ((err) (c1 nil))
    ;; Copy p1 into registers.
    (dotimes (i 16)
      (setf (aref *aes-128-cfbe-p1* i) (pop p1)))
    ;; Call int aes_128_cipher (huge c1, huge p1);
    (setf err (external-call "_aes_128_cipher"
      :address *aes-128-cfbe-c1-ptr*
      :address *aes-128-cfbe-p1-ptr*
      :unsigned-int))
    ;; Check for errors.
    (if (not (= 0 err))
	(error "_aes_128_cipher returned ~A" err))
    ;; Copy registers into c1.
    (dotimes (i 16)
      (push (aref *aes-128-cfbe-c1* i) c1))
    ;; Evaluate c1.
    (reverse c1)))


;;;
;;; aes-128-cfbe
;;; This is a Lisp wrapper for the C function.
;;; Input p1 is a 16-element list of 8-bit unsigned integers.
;;; Evaluates to c1, a 16-element list of 8-bit unsigned integers.
;;;

(defun aes-128-cfbe (p1)
  (let ((err) (c1 nil))
    ;; Copy p1 into registers.
    (dotimes (i 16)
      (setf (aref *aes-128-cfbe-p1* i) (pop p1)))
    ;; Call int aes_128_encode (huge c1, huge p1, huge c0)
    (setf err (external-call "_aes_128_cfbe"
      :address *aes-128-cfbe-c1-ptr*
      :address *aes-128-cfbe-p1-ptr*
      :address *aes-128-cfbe-c0-ptr*
      :unsigned-int))
    ;; Check for errors.
    (if (not (= 0 err))
	(error "_aes_128_cfbe returned ~A" err))
    ;; Copy registers into c1.
    (dotimes (i 16)
      (push (aref *aes-128-cfbe-c1* i) c1))
    ;; Evaluate c1.
    (reverse c1)))


;;;
;;; aes-128-cfbd
;;; This is a Lisp wrapper for the C function.
;;; Input c1 is a 16-element list of 8-bit unsigned integers.
;;; Evaluates to p1, a 16-element list of 8-bit unsigned integers.
;;;

(defun aes-128-cfbd (c1)
  (let ((err) (p1 nil))
    ;; Copy c1 into registers.
    (dotimes (i 16)
      (setf (aref *aes-128-cfbd-c1* i) (pop c1)))
    ;; Call int aes_128_decode (huge p1, huge c1, huge c0)
    (setf err (external-call "_aes_128_cfbd"
      :address *aes-128-cfbd-p1-ptr*
      :address *aes-128-cfbd-c1-ptr*
      :address *aes-128-cfbd-c0-ptr*
      :unsigned-int))
    ;; Check for errors.
    (if (not (= 0 err))
	(error "_aes_128_cfbd returned ~A" err))
    ;; Copy registers into p1.
    (dotimes (i 16)
      (push (aref *aes-128-cfbd-p1* i) p1))
    ;; Evaluate p1.
    (reverse p1)))


;;;
;;; aes-128-expand-test
;;; Tests the aes-128-expand function.
;;; Uses a list of test vectors in Test/aes-expand.vec.
;;; Each test vector is a list containing a 128-bit integer
;;; and a 44-element array of 32-bit integers.
;;;

(defun aes-128-expand-test ()
  (let ((v) (k) (w) (z))
    (setf v (getlist "../Test/aes-expand.vec"))
    (dotimes (i (length v))
      (setf k (nth 0 (nth i v)))
      (setf w (nth 1 (nth i v)))
      (setf z (aes-128-expand k))
      (if (not (equal-arrays w z))
	  (error "FAILED on k=~A" k)))
    T))


;;;
;;; aes-128-cipher-test
;;; Tests the aes-128-cipher function.
;;; Uses a list of test vectors in Test/aes-cipher.vec.
;;; Each test vector is a list containing a plaintext list 
;;; and a ciphertext list.
;;;

(defun aes-128-cipher-test ()
  (let ((v) (k) (p) (c) (z))
    (setf v (getlist "../Test/aes-cipher.vec"))
    (dotimes (i (length v))
      (setf k (nth 0 (nth i v)))
      (setf p (nth 1 (nth i v)))
      (setf c (nth 2 (nth i v)))
      (aes-128-expand k)
      (setf z (unite-int (aes-128-cipher (split-int 16 p))))
      (if (not (= c z)) (error "FAILED on k=~A" k)))
    T))


;;;
;;; aes-128-cfbe-test
;;; Tests the aes-128-cfbe function.
;;; Uses a list of test vectors in Test/aes-encode.vec.
;;; Each vector is a list containing three lists: c0 p1 c1.
;;; c0 is either NIL or a 16-element list of 8-bit unsigned integers.
;;; p1 is a 16-element list of 8-bit unsigned integers.
;;; c1 is a 16-element list of 8-bit unsigned integers.
;;; These vectors were generated using the old aes-128-cipher function
;;; along with an exclusive-OR function and a copy from c1 to c0.
;;;

(defun aes-128-cfbe-test ()
  (let ((v) (k) (c0) (p1) (c1) (c2))
    (setf v (getlist "../Test/aes-encode.vec"))
    (dotimes (i (length v))
      (setf k (nth 0 (nth i v)))
      (setf c0 (nth 1 (nth i v)))
      (setf p1 (nth 2 (nth i v)))
      (setf c1 (nth 3 (nth i v)))
      (aes-128-expand k)
      (if (not (null c0)) (aes-128-inite c0))
      (setf c2 (aes-128-cfbe p1))
      (if (not (equal c1 c2)) (error "FAILED on k=~A" k)))
    T))
  

;;;
;;; aes-128-cfbd-test
;;; Tests the aes-128-cfbd function.
;;; Uses a list of test vectors in Test/aes-decode.vec.
;;; Each vector is a list containing three lists: c0 c1 p1.
;;; c0 is either NIL or a 16-element list of 8-bit unsigned integers.
;;; c1 is a 16-element list of 8-bit unsigned integers.
;;; p1 is a 16-element list of 8-bit unsigned integers.
;;; These vectors were generated using the old aes-128-cipher function
;;; along with an exclusive-OR function and a copy from c1 to c0.
;;;

(defun aes-128-cfbd-test ()
  (let ((v) (k) (c0) (c1) (p1) (p2))
    (setf v (getlist "../Test/aes-decode.vec"))
    (dotimes (i (length v))
      (setf k (nth 0 (nth i v)))
      (setf c0 (nth 1 (nth i v)))
      (setf c1 (nth 2 (nth i v)))
      (setf p1 (nth 3 (nth i v)))
      (aes-128-expand k)
      (if (not (null c0)) (aes-128-initd c0))
      (setf p2 (aes-128-cfbd c1))
      (if (not (equal p1 p2)) (error "FAILED on k=~A" k)))
    T))


;;;
;;; aes-okayp
;;;

(defun aes-okayp ()
  (aes-reset)
  (and (aes-128-expand-test)
       (aes-128-cipher-test)
       (aes-128-cfbe-test)
       (aes-128-cfbd-test)))

