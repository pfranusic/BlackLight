;;;; random.lisp
;;;;


#||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||

This is the current code in BlackLight/OpenPGP/Code/stdlib.lisp.

;;;
;;; true-random-32
;;; returns a random integer in [0, 2^{32}-1].
;;; This function is currently specified by dummy code.
;;; It will eventually be replaced by code that accesses
;;; a dynamic library function which provides 32 true random bits.
;;;

(defun true-random-32 ()
  (random 4294967296))


The following is the proposed replacement code.

||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||#


;;;
;;; true-random-32
;;; returns a random integer in [0, 2^{32}-1].
;;; This function is implemented by code that 
;;; accesses a dynamic library function which 
;;; provides 32 pseudo-random bits from the 
;;; C stdlib arc4random function.
;;;

(defun true-random-32 ()
  (let ((rng-dat) (rng-ptr) (n) (err))
    (open-shared-library "random.dylib")
    (multiple-value-bind (lnd lnp)
			 (make-heap-ivector 1 '(unsigned-byte 32))
			 (setq rng-dat lnd)
			 (setq rng-ptr lnp))
    (setf err (external-call "_true_random_32"
			     :address rng-ptr
			     :unsigned-int))
    (if (not (= 0 err)) (error "_true_random_32 returned ~A" err))
    (setf n (aref rng-dat 0))
    (dispose-heap-ivector rng-dat)
    ;; (close-shared-library "random.dylib")
    ;; Warning: Dynamic libraries cannot be closed on Darwin.
    n))


