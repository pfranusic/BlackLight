;;;; BlackLight/OpenPGP/stdlib.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; Standard library functions
;;;;


;;;
;;; while	     
;;; See Graham 1996 "ANSI Common Lisp" section 10.4
;;;

(defmacro while (test &rest body)
  `(do ()
       ((not ,test))
       ,@body))


;;;
;;; memberp
;;; returns T if e is a member of l.
;;;

(defun memberp (l e)
  (dotimes (i (length l))
    (if (equal e (nth i l))
	(return-from memberp T)))
  nil)


;;;
;;; in-between
;;; returns T iff $a <= b <= c$, else return NIL.
;;;

(defun in-between (a b c)
  (if (and (<= a b) (<= b c)) T NIL))


;;;
;;; quo
;;; returns the quotient part of a division operation.
;;; rem return the remainder part.
;;;

(defun quo (dividend divisor)
    (/ (- dividend (rem dividend divisor)) divisor))


;;;
;;; checksum
;;; Input is a list of bytes.
;;; Output is a 16-bit integer.
;;;

(defun checksum (x)
  (if (not (blistp x)) (error "x must be a list of bytes"))
  (let ((y 0))
    (dotimes (i (length x))
      (setf y (+ y (nth i x))))
    (mod y 65536)))


;;;
;;; random-bytes
;;; given an unsigned integer n,
;;; returns a list with n elements,
;;; where each element is a random byte.
;;;

(defun random-bytes (n)
  (let ((z nil))
    (dotimes (i n)
      (push (random 256) z))
    z))


;;;
;;; random-nonzero-bytes
;;; given an unsigned integer n,
;;; returns a list with n elements,
;;; where each element is a random non-zero byte.
;;;

(defun random-nonzero-bytes (n)
  (let ((x) (y nil))
    (dotimes (i n)
      (while (= 0 (setf x (random 256))))
      (push x y))
    y))


;;;
;;; nbits
;;; returns the number of bits in an integer.
;;; Ex: (nbits 256) => 9
;;; Ex: (nbits 255) => 8
;;; Ex: (nbits (expt 2 2048)) => 2049
;;; Ex: (nbits (1- (expt 2 2048))) => 2048
;;;

(defun nbits (nn)
  (if (not (integerp nn)) (return-from nbits 0))
  (if (< nn 0) (return-from nbits 0))
  (if (= nn 0) (return-from nbits 1))
  (let ((n (ceiling (log nn 2))))
    (if (logbitp n nn) (+ 1 n) n)))


;;;
;;; nbytes
;;; returns the number of bytes in an integer.
;;; Ex: (nbytes 255) => 1
;;; Ex: (nbytes 256) => 2
;;; Ex: (nbytes (1- (expt 2 2048))) => 256
;;; Ex: (nbytes (expt 2 2048)) => 257
;;;

(defun nbytes (n)
  (if (or (not (integerp n))
	  (< n 0))
      (error "n must be a positive integer"))
  (if (= n 0) (return-from nbytes 1))
  (if (= 0 (rem (nbits n) 8)) (quo (nbits n) 8)
    (1+ (quo (nbits n) 8))))


;;;
;;; blistp
;;; returns T iff m is a non-empty list of 8-bit integers.
;;;

(defun blistp (m)
  (if (not (listp m)) (return-from blistp NIL))
  (if (= 0 (length m)) (return-from blistp NIL))
  (let ((q))
    (dotimes (i (length m))
      (progn
	(setf q (pop m))
	(if (or (not (integerp q))
		(< q #x00)
		(> q #xFF))
	    (return-from blistp NIL))))
  T))


;;;
;;; decimal-digit-p
;;; returns T iff character c is in [0,9].
;;;

(defun decimal-digit-p (c)
  (if (not (characterp c))
      (error "c must be a character"))
  (let ((x (- (char-code c) 48)))
    (if (and (<= 0 x) (<= x 9))
	T nil)))


;;;
;;; upper-alpha-p
;;; returns T iff character c is in [A,Z].
;;;

(defun upper-alpha-p (c)
  (if (not (characterp c)) (error "c must be a character"))
  (if (in-between (char-code #\A) (char-code c) (char-code #\Z))
      T nil))


;;;
;;; lower-alpha-p
;;; returns T iff character c is in [a,z].
;;;

(defun lower-alpha-p (c)
  (if (not (characterp c)) (error "c must be a character"))
  (if (in-between (char-code #\a) (char-code c) (char-code #\z))
      T nil))


;;;
;;; print-all-ascii
;;; prints a string with all of the printable ASCII characters.
;;; I.e., prints all of the characters between SPACE and DEL.
;;;

(defun print-all-ascii ()
  (let ((s ""))
    (do ((i 33 (1+ i))) ((> i 126))
	(setf s (format nil "~A~A" s (code-char i))))
    s))


;;;
;;; random-ascii-code
;;; returns an ASCII code that has been randomly selected.
;;; We want to return an integer in [33,126].
;;; (random 94) generates a random integer in [0,93].
;;;

(defun random-ascii-code ()
  (+ 33 (random 94)))


;;;
;;; listn
;;; returns a list containing n copies of the value x.
;;;

(defun listn (n x)
  (if (< n 1) (return-from listn nil))
  (let ((y nil))
    (dotimes (i n)
      (push x y))
    y))


;;;
;;; hex-stringp
;;; returns T iff s is a hex string,
;;; i.e., a string of hexadecimal characters.
;;;

(defun hex-stringp (s)
  (if (not (stringp s)) (return-from hex-stringp nil))
  (if (= 0 (length s)) (return-from hex-stringp nil))
  (dotimes (i (length s))
    (if (not (memberp '(#\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9
			#\A #\B #\C #\D #\E #\F
			#\a #\b #\c #\d #\e #\f)
		      (aref s i)))
	(return-from hex-stringp nil)))
  T)


;;;
;;; bump
;;; returns either $n+2$ or $n+4$ given $n$.
;;; depending on the least-significant decimal digit.
;;; (bump ...1) => ...3, (bump ...3) => ...7,
;;; (bump ...7) => ...9, (bump ...9) => ...1.
;;;

(defun bump (n)
  (if (not (integerp n)) (return-from bump n))
  (let ((r (rem n 10)))
    (if (= 0 (rem r 2)) (+ n 1)
      (if (or (= r 1) (= r 5) (= r 7) (= r 9)) (+ n 2)
	(+ n 4)))))


;;;
;;; true-random-32
;;; returns a random integer in [0, 2^{32}-1].
;;; This function is currently specified by dummy code.
;;; It will eventually be replaced by code that accesses
;;; a dynamic library function which provides 32 true random bits.
;;;

(defun true-random-32 ()
  (random 4294967296))


;;;
;;; random-between
;;; takes two floats and returns a random float in [a,b], or [b,a].
;;;

(defun random-between (a b)
  (if (not (numberp a)) (error "a must be a number"))
  (if (not (numberp b)) (error "a must be a number"))
  (let ((w (abs (- a b)))
	(x (/ (float (random 4294967296)) 4294967296.0)))
    (if (< a b) (+ a (* w x)) (+ b (* w x)))))


;;;
;;; log2
;;; returns the log base 2 of the argument
;;;

(defun log2 (x)
  (log x 2))


;;;
;;; equal-arrays
;;;

(defun equal-arrays (a b)
  (if (not (and (arrayp a)
		(arrayp b)
		(= (length a) (length b))))
      (return-from equal-arrays NIL))
  (dotimes (i (length a))
    (if (/= (aref a i) (aref b i))
	(return-from equal-arrays NIL)))
  T)


;;;
;;; zeros
;;; returns a list with n zeros
;;;

(defun zeros (n)
  (let ((y nil))
    (dotimes (i n)
      (push 0 y))
    y))


;;;
;;; stdlib-okayp
;;;

(defun stdlib-okayp ()
  (and (= 3 (quo 27 8))
       (= 2049 (nbits (expt 2 2048)))
       (= 257 (nbytes (expt 2 2048)))
       (blistp '(0 127 255))
       (not (blistp '(-1 127 257)))
       (decimal-digit-p #\0)
       (not (decimal-digit-p #\a))
       (lower-alpha-p #\a)
       (not (lower-alpha-p #\A))))

