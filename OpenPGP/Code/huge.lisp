;;;; BlackLight/OpenPGP/huge.lisp
;;;; Copyright 2012 Peter Franusic
;;;;


;;;
;;; huge-expt
;;; takes a float x and returns an integer approximately equal to 2^x.
;;; We want to be able to compute huge powers of 2 with floating-point exponents.
;;; The problem is that the built-in function "expt" can't handle large exponents.
;;; For example, (expt 2 4095.995) gives this error message:
;;; "FLOATING-POINT-OVERFLOW detected performing EXPT on (2.0D0 4095.9951171875D0)".
;;; But (expt 2 4095) works fine, so the problem is the fractional part of 4095.995.
;;; But we can work around the problem.  The idea is to use the identity
;;; 2^a * 2^b = 2^{a+b} and compute (* (expt 2 a) (expt 2 b)),
;;; where a is the integer part of x and b is the fractional part of x.
;;; However, a floating-point multiply won't work on such large numbers.
;;; But an integer multiply WILL work.
;;; So we need to adjust things accordingly.
;;; We set a to (floor x) and subtract 127, so it's still an integer.
;;; We set b to (- x a), making it a float in [127.0, 128.0).
;;; Then we compute (expt 2 a) which is an integer, and
;;; we compute (round (expt 2 b)) which is also an integer.
;;; Finally we multiply the two exponentiated integers to get the result.
;;; Ex: (log (huge-expt 4095.997) 2) -> 4095.997
;;;

(defun huge-expt (x)
  (if (<= x 127.0) (error "x must be greater than 127"))
  (let ((a) (b)) 
    (setf a (- (floor x) 127))
    (setf b (- x a))
    (* (expt 2 a) (round (expt 2 b)))))


;;;
;;; random-decryptor
;;; returns a random integer in [0, lambda-1]
;;; and relatively prime to lambda.
;;;

(defun random-decryptor (lambda)
  (let ((d lambda))
    (while (/= 1 (gcd d lambda))
      (setf d (random lambda)))
    d))


;;;
;;; mod-inverse
;;; returns the modular inverse $\dot{a}$ such that,
;;; given modulus $n$ and $a,\dot{a} \in Z_n$, $a \otimes \dot{a} = 1$.
;;;

(defun mod-inverse (n a)
  (let ((a1 1) (a2 a) (n1 0) (n2 n) (q 0) (r 0))
    (do ()
	((<= n2 0) (+ a1 (if (< a1 0) n 0)))
	(setf q (truncate a2 n2))
	(setf r (- a1 (* n1 q)))
	(setf a1 n1)
	(setf n1 r)
	(setf r (- a2 (* n2 q)))
	(setf a2 n2)
	(setf n2 r))))


;;;
;;; L-sub-n
;;; evaluates the equation $L_n[u,v] = e^{v (\ln x)^u (\ln \ln x)^{1-u}}$
;;; See \emph{Integer Factoring}, Arjen K. Lenstra, 2000, page 3.
;;;

(defun L-sub-n (u v n)
  (let ((e1 v)
	(e2 (expt (log n) u))
	(e3 (expt (log (log n)) (- 1 u))))
    (exp (* e1 e2 e3))))


;;;
;;; (L-sub-n-plot u v nd incr last)
;;; plots points using the L-sub-n function for each integer.
;;; It starts with integer length $nd$
;;; and increments the length by $incr$ until $last$ is reached.
;;;

(defun L-sub-n-plot (u v nd incr last)
  (let ((y))
    (do ((x nd (+ x incr))) ((> x last) 'end)
	(setf y  (L-sub-n u v (expt 10 x)))
	(setf y  (- (log y 10) 7.45))
	(setf y  (/ (round (* y 100)) 100.0))
	(format t "x=~A y=~A~%" x y))))


;;;
;;; shor-plot
;;; plots points for Shor's algorithm time complexity $\mathcal{O}((\ln N)^3)$.
;;;

(defun shor-plot (nd incr last)
  (let ((y))
    (do ((x nd (+ x incr))) ((> x last) 'end)
	(setf y (expt (log (expt 10 x)) 3))
	(setf y  (- (log y 10) 7.45))
	(setf y (/ (round (* y 100)) 100.0))
	(format t "x=~A y=~A~%" x y))))


;;;
;;; huge-okayp
;;;

(defun huge-okayp ()
  (and (= 4095.997 (log (huge-expt 4095.997) 2))
       (= 1 (otimes (mod-inverse 65447 65437) 65437 65447))))


