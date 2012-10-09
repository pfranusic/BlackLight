;;;; BlackLight/OpenPGP/modex.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; This file contains code for the modex function.
;;;; modex calls two custom functions, otimes and msbno.
;;;; modex-okayp tests the modex function.
;;;; 


;;;
;;; oplus 
;;; returns the mod n sum of a and b.
;;; Ex: (oplus 25 17 33) => 9
;;;

(defun oplus (a b n)
  (rem (+ (rem a n) (rem b n)) n))


;;;
;;; otimes
;;; returns the mod n product of a and b.
;;; Ex: (otimes 25 17 33) => 29
;;;

(defun otimes (a b n)
  (rem (* (rem a n) (rem b n)) n))


;;;
;;; totient
;;; returns the totient function value $\Phi(pq)$.
;;;

(defun totient (p q)
  (* (- p 1) (- q 1)))


;;;
;;; carmichael
;;; returns the Carmichael function value $\lambda(pq)$.
;;; This is easy because the lcm function is already defined.
;;; Ex: (carmichael 3 11) => 10
;;;

(defun carmichael (p q)
  (lcm (- p 1) (- q 1)))


;;;
;;; msbno
;;; returns the bit position of the msb of x.
;;; The do list has two arguments.
;;; The first argument has two expressions "(y 1 (* y 2))" and "(n 0 (+ n 1))".
;;; The first expression initializes y to 1 and then multiplies it by 2 on each iteration.
;;; The second expression initializes n to 0 and then increments it on each iteration. 
;;; The second argument has two expresstions "(> y x)" and "(- n 1)".
;;; The first expression tests whether y is greater than x.
;;; The second expression is evaluated when the first expression is true.
;;; It decrements n and returns the result.
;;; Ex: (msbno 4096) => 12
;;;

(defun msbno (x)
  (do ((y 1 (* y 2))
       (n 0 (+ n 1)))
      ((> y x) (1- n))))


;;;
;;; modex ["simple" modex]
;;; returns the modular product of the base to the exponent power.
;;; modex is implemented using the square-and-multiply algorithm.
;;; We start by setting the local register "r" to the base.
;;; This is because the most-significant bit (msb) of any exponent is a 1.
;;; We also initialize the local variable "msb" (msb number) with the
;;; bit number of the msb in the exponent x.
;;; Then, while the msb is greater than or equal to 0, we do three or four things:
;;; [1] We square r and and reduce it with the modulus n.
;;; [2] We test exponent x for a 1 in the bit position specified by msb.
;;; [3] If the bit is there, we multiply r by the base a and reduce it with the modulus n.
;;; [4] We decrement msb.
;;; Ex: (modex 25 17 33) => 31
;;;

(defun modex (a x n)
  (do ((r 1) (msb (msbno x) (- msb 1))) ((< msb 0) r)
      (setf r (otimes r r n))
      (if (logbitp msb x)
	  (setf r (otimes r a n)))))


;;;
;;; modex-okayp
;;; returns T iff all tests pass.
;;; Otherwise returns NIL.
;;; We use the RSA identity $x = (x^e)^d \bmod n$.
;;; We use random values for $x$.
;;; We use pre-computed values for n, e, d.
;;; p=16057866021918009221, q=19770164981081643187.
;;;

(defun modex-okayp ()
  (let ((n 317466660497424219712697687926497827327)
	(e 276390137396303902597713702832238530687)
	(d 135654633782103522354315028092696454303)
	(x) (y) (z))
    (dotimes (i 40)
      (setf x (random n))
      (setf y (modex x e n))
      (setf z (modex y d n))
      (if (/= x z) (return-from modex-okayp NIL)))
    T))

