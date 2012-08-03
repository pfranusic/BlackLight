;;;; BlackLight/OpenPGP/prime-pair.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; Lisp code to generate strong prime pairs.
;;;;


;;;
;;; blank-lower
;;; zeroes the lower n bits in x.
;;; Ex: (int-hex (blank-lower 224 (random (expt 2 256))))
;;;

(defun blank-lower (n x)
  (- x (logand x (- (expt 2 n) 1))))


;;;
;;; random-bits
;;; returns an integer consisting of n random bits.
;;; Ex: (int-hex (random-bits 141))
;;;

(defun random-bits (n)
  (if (not (integerp n)) (error "n must be an integer"))
  (if (not (> n 0)) (error "n must be greater than 0"))
  (let ((i n) (y 0))
    (while (> i 32)
      (setf y (+ (* y 4294967296) (true-random-32)))
      (setf i (- i 32)))
    (if (> i 0)
	(setf y (+ (* y (expt 2 i)) (logand (true-random-32) (- (expt 2 i) 1)))))
    y))


;;;
;;; random-integer
;;; takes a float x and returns a random integer in [2^x - e, 2^x + e],
;;; where e is much smaller than 2^x, approximately 1/65536 of 2^x.
;;; Ex: (int-hex (random-integer 1023.995))
;;; When the preceding expression is evaluated several times,
;;; the most-significant 4 digits (16 bits) will always be "FF1D"
;;; and the remaining 252 digits (1008 bits) will always be random.
;;;

(defun random-integer (x)
  (if (not (floatp x)) (error "x must be a float"))
  (if (not (> x 64.0)) (error "x must be greater than 64.0"))
  (let ((n (- (floor x) 15)) (y (huge-expt x)))
    (+ (blank-lower n y) (random-bits n))))


;;;
;;; has-no-tiny-factors
;;; returns T iff n has no prime factors less than 12.
;;; It is efficiently implemented using the built-in gcd function.
;;; (* 2 3 5 7 11) -> 2310
;;;

(defun has-no-tiny-factors (n)
  (= 1 (gcd n 2310)))


;;;
;;; has-large-prime-factor
;;; This function need to be implemented.
;;; It will require a list of the prime factors of n.
;;; It will require a specification of the minimum value.
;;;

(defun has-large-prime-factor (n)
  (if (= n n) T T))


;;;
;;; strong-prime
;;; returns a strong random prime integer whose log base 2 is x.
;;; This function is only partially implemented.
;;; It requires several decisions on what tests to perform.
;;; See: Schneier 1994, Section 9.5, "Prime Number Generation".
;;; Ex: (strong-prime 127.9)
;;;

(defun strong-prime (x)
  (let ((p (random-integer x)) (z nil))
    (while (not z)
      (setf p (bump p))
      (setf z (and (has-no-tiny-factors (/ (1- p) 2))
		   (primep p)
		   (has-large-prime-factor (1- p))
		   (has-large-prime-factor (1+ p)))))
    p))


;;;
;;; prime-pair
;;; returns a list of two huge primes, p and q,
;;; which comply with a set of rigid criteria.
;;; Input is the float log2-n, the log base 2
;;; desired for the future modulus n = p * q.
;;; Ex: (prime-pair 299.5)
;;;

(defun prime-pair (log2-n)
  (if (not (and (floatp log2-n) (> log2-n 255.0)))
      (error "log2-n must be a float greater than 255.0"))
  (let ((log2-p (- (/ log2-n 2.0) 0.001))
	(log2-q (+ (/ log2-n 2.0) 0.001))
	(p) (q) (phi 100) (lam 10))
    (while (/= phi (* 2 lam))
      (setf p (strong-prime log2-p)) 
      (setf q (strong-prime log2-q))
      (setf phi (totient p q))
      (setf lam (carmichael p q)))
    (list p q)))


;;;
;;; pair-okayp
;;;

(defun pair-okayp ()
  (in-between 127.899 (log2 (random-integer 127.9)) 127.901))


