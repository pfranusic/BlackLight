;;;; BlackLight/OpenPGP/cfb.lisp
;;;; Copyright 2012 Peter Franusic
;;;;


;;;
;;; cfb-128-encode
;;; Implements the CFB encode algorithm inferred from RFC-4880 section 13.9 for $BS=16$.
;;; Utilizes the aes-128-cfbe wrapper function.
;;; Input k is a 128-bit unsigned integer.
;;; Input r is either a list of 16 random bytes, or is simply NIL.
;;; Input p is a list of plaintext bytes.
;;; Evaluates to c, a list of ciphertext bytes.
;;; 

(defun cfb-128-encode (k r p)
  (let ((x nil) (c nil) (n))

    ;;; Make sure session key k is really a 128-bit unsigned integer.
    ;;; Then create key schedule w from k.
    (if (not (and (integerp k) (plusp k) (< (log k 2) 128)))
	(error "k must be a positive integer less than 2^128"))
    (aes-128-expand k)

    ;;; Make sure random list r is really a list.
    ;;; Then if r is nil, fill it with 16 random bytes.
    (if (not (listp r))
	(error "r must be a list"))
    (if (null r) (setf r (random-bytes 16)))

    ;;; Make sure plaintext list p is really a list of bytes.
    ;;; Then count the number of elements in p.
    (if (not (blistp p))
	(error "p must be a non-empty list of bytes"))
    (setf n (length p))

    ;;; Compute the first 16 bytes of ciphertext list c.
    ;;; $x = R \oplus \kappa(0)$.
    (aes-128-inite (zeros 16))
    (setf x (aes-128-cfbe r))
    (setf c x)

    ;;; Compute the next 2 bytes of c.
    ;;; $x = \msw(\kappa(x)) \oplus \lsw(R)$.
    ;;; Resynch the feedback with $c_2 c_3 \ldots c_18$.
    (setf x (split-int 2
	      (logxor (unite-int (subseq (aes-128-cipher x) 0 2))
		      (unite-int (subseq r 14 16)))))
    (setf c (append c x))
    (aes-128-inite (subseq c 2 18))
    (setf c (reverse c))

    ;;; While there are at least 16 bytes in plaintext list p,
    ;;; compute the next 16 bytes of ciphertext list p.
    ;;; $C_i = P_i \oplus \kappa(C_{i-1})$.
    (while (>= n 16)
      (setf x (aes-128-cfbe (subseq p 0 16)))
      (dotimes (i 16) (push (pop x) c))
      (dotimes (i 16) (pop p))
      (setf n (- n 16)))

    ;;; If p is empty then return.
    ;;; Compute the last n bytes of c from the last n bytes in p.
    ;;; Use $16-n$ dummy bytes in the least-significant bits.
    ;;; $C_i = P_i \oplus \kappa(c_{i-1})$.
    ;;; Return c.
    (if (= 0 n) (return-from cfb-128-encode (reverse c)))
    (setf x (subseq (aes-128-cfbe (append p (zeros (- 16 n)))) 0 n))
    (dotimes (i n) (push (pop x) c))
    (dotimes (i n) (pop p))
    (reverse c)))


;;;
;;; cfb-128-encode-test
;;; 

(defun cfb-128-encode-test ()
  (let ((v) (k) (r) (x) (y) (z))
    (setf v (getlist "../Test/cfb-test.data"))
    (dotimes (i (length v))
      (setf k (nth 0 (nth i v)))
      (setf r (nth 1 (nth i v)))
      (setf x (nth 2 (nth i v)))
      (setf y (nth 3 (nth i v)))
      (setf z (cfb-128-encode k r x))
      (if (not (equal y z))
	  (error "FAILED on k=~A" k)))
    'PASSED))


;;;
;;; cfb-128-decode
;;; Implements the CFB decode algorithm inferred from RFC-4880 section 13.9 for $BS=16$.
;;; Utilizes the aes-128-cfbd wrapper function.
;;; Input k is a 128-bit unsigned integer.
;;; Input c is a list of ciphertext bytes.
;;; Evaluates to p, a list of plaintext bytes.
;;;

(defun cfb-128-decode (k c)
  (let ((x nil) (p nil) (n) (r))

    ;;; Make sure session key k is really a 128-bit unsigned integer.
    ;;; Then create key schedule w from k.
    (if (not (and (integerp k) (plusp k) (< (log k 2) 128)))
	(error "k must be a positive integer less than 2^128"))
    (aes-128-expand k)

    ;;; Make sure ciphertext list c is really a list of at least 18 bytes.
    ;;; Then count the number of elements in c.
    (if (not (and (blistp c) (>= (length c) 18)))
	(error "c must be a list of bytes with at least 18 elements"))
    (setf n (length c))

    ;;; $C_x$ is the first 16 bytes of ciphertext list c.
    ;;; Compute random $R = C_x \oplus \kappa(0)$.
    (setf x (subseq c 0 16))
    (aes-128-initd (zeros 16))
    (setf r (aes-128-cfbd x))

    ;;; Verify that the two-byte random words match.  I.e.,
    ;;; $\msw(\kappa(C_x)) \oplus \lsw(R) = 256 \cdot c_{17} + c_{18}$.
    ;;; Resynch the feedback with $c_2 c_3 \ldots c_18$.
    (if (/= (logxor (unite-int (subseq (aes-128-cipher x) 0 2))
		    (unite-int (subseq r 14 16)))
	    (unite-int (subseq c 16 18)))
	(return-from cfb-128-decode NIL))
    (aes-128-initd (subseq c 2 18))
    (dotimes (i 18) (pop c))
    (setf n (- n 18))

    ;;; While there are at least 16 bytes in ciphertext list c,
    ;;; compute the next 16 bytes of plaintext list p.
    ;;; $P_i = C_i \oplus \kappa(C_{i-1})$.
    (while (>= n 16)
      (setf x (aes-128-cfbd (subseq c 0 16)))
      (dotimes (i 16) (push (pop x) p))
      (dotimes (i 16) (pop c))
      (setf n (- n 16)))

    ;;; If c is empty then return.
    ;;; Compute the last n bytes of p from the last n bytes in c.
    ;;; Use $16-n$ dummy bytes in the least-significant bits.
    ;;; $P_i = C_i \oplus \kappa(C_{i-1})$.
    ;;; Return p.
    (if (= 0 n) (return-from cfb-128-decode (reverse p)))
    (setf x (subseq (aes-128-cfbd (append c (zeros (- 16 n)))) 0 n))
    (dotimes (i n) (push (pop x) p))
    (dotimes (i n) (pop c))
    (reverse p)))
      

;;;
;;; cfb-128-decode-test
;;; 

(defun cfb-128-decode-test ()
  (let ((v) (k) (x) (y) (z))
    (setf v (getlist "../Test/cfb-test.data"))
    (dotimes (i (length v))
      (setf k (nth 0 (nth i v)))
      (setf x (nth 2 (nth i v)))
      (setf y (nth 3 (nth i v)))
      (setf z (cfb-128-decode k y))
      (if (not (equal x z))
	  (error "FAILED on k=~A" k)))
    'PASSED))


;;;
;;; cfb-okayp
;;; Tests the cfb-128-encode and cfb-128-decode functions.
;;; Randomly generates a plaintext list x, 
;;; calls cfb-128-encode to produce a ciphertext list y,
;;; calls cfb-128-decode to produce a plaintext list z,
;;; then compares x and z.
;;; Evaluates to either T or NIL.
;;;

(defun cfb-okayp ()
  (let ((k) (r) (x) (y) (z))
    (setf k (random (expt 2 128)))
    (setf r (random-bytes 16))
    (setf x (random-bytes (+ 10000 (random 100))))
    (setf y (cfb-128-encode k r x))
    (setf z (cfb-128-decode k y))
    (equal x z)))

