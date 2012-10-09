;;;; BlackLight/OpenPGP/sha.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; Implements SHA algorithms specified in NIST FIPS PUB 180-2.
;;;; 


;;;; 
;;;; Operations on Words
;;;; (See FIPS PUB 180-2 section 3.2).
;;;; The following operations are applied to 32-bit words.
;;;; 1. Bitwise logical operators: logand, logior, logxor, and lognot.
;;;; 2. Addition modulo (expt 2 32): (mod (+ a b c) (expt 2 32)).
;;;; 3. The shift right operation sha-SHR.
;;;; 4. The rotate right operation sha-ROTR.
;;;; 5. The rotate left operation sha-ROTL.
;;;; 


;;;
;;; sha-SHR
;;; takes a 32-bit integer x and shifts all bits n places to the right.
;;; Zeros are entered from the left. Uses the built-in ASH function.
;;;

(defun sha-SHR (n x)
  (ash x (- 0 n)))


;;;
;;; sha-ROTR
;;; takes a 32-bit integer x and rotates all bits n places to the right.
;;;

(defun sha-ROTR (n x)
  (logior (logand #xFFFFFFFF (ash x (- 32 n)))
	  (ash (logand x #xFFFFFFFF) (- 0 n))))


;;;
;;; sha-ROTL
;;; takes a 32-bit integer x and rotates all bits n places to the left.
;;; This operation is used only in the SHA-1 algorithm.
;;;

(defun sha-ROTL (n x)
  (logior (logand #xFFFFFFFF (ash x n))
	  (ash (logand x #xFFFFFFFF) (- n 32))))



;;;; 
;;;; SHA functions
;;;; (See FIPS PUB 180-2 section 4.1).
;;;; SHA-1 uses three logical functions: Ch, Parity, and Maj.
;;;; Each operates on three 32-bit words x, y, and z
;;;; and produces a 32-bit word as output.
;;;; SHA-256 uses the two logical functions Ch and Maj.
;;;; Each operates on three 32-bit words x, y, and z
;;;; and produces a 32-bit word as output.
;;;; 


;;;
;;; sha-ch-32
;;; takes the three 32-bit integers x y z
;;; and returns ((x and y) xor ((not x) and z)).
;;; 32-bit inversion is implemented using logxor #xFFFFFFFF.
;;;

(defun sha-ch-32 (x y z)
  (logxor (logand x y) (logand (logxor x #xFFFFFFFF) z)))


;;;
;;; sha-maj-32
;;; takes the three 32-bit integers x y z
;;; and returns ((x and y) xor (x and z) xor (y and z)).
;;;

(defun sha-maj-32 (x y z)
  (logxor (logand x y) (logand x z) (logand y z)))


;;;
;;; sha-parity-32
;;; takes the three 32-bit integers x y z
;;; and returns (x xor y xor z).
;;;

(defun sha-parity-32 (x y z)
  (logxor x y z))


;;;;
;;;; BlackLight OpenPGP code for SHA-1
;;;; structures: *sha1-k* *sha1-h* *sha1-n* *sha1-q* *sha1-r*
;;;; functions: sha1-qlen sha1-f sha1-calc sha1-proc
;;;;            sha1-reset sha1-bits sha1-bytes sha1-hash
;;;;


;;;
;;; *sha1-k*
;;; (See FIPS PUB 180-2 section 4.2.1, "SHA-1 Constants").
;;; SHA-1 uses a sequence of eighty constant 32-bit words $K_0, K_1, \ldots, K_{79}$.
;;; We represent these in a vector in order to speed up access.
;;; Use the svref operator to access vector elements.
;;;

(defconstant *sha1-k* (vector
  #x5A827999 #x5A827999 #x5A827999 #x5A827999 #x5A827999 ;  0 <= t <= 19
  #x5A827999 #x5A827999 #x5A827999 #x5A827999 #x5A827999
  #x5A827999 #x5A827999 #x5A827999 #x5A827999 #x5A827999
  #x5A827999 #x5A827999 #x5A827999 #x5A827999 #x5A827999
  #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 ; 20 <= t <= 39
  #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1
  #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1
  #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1 #x6ED9EBA1
  #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC ; 40 <= t <= 59
  #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC
  #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC
  #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC #x8F1BBCDC
  #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 ; 60 <= t <= 79
  #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 #xCA62C1D6
  #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 #xCA62C1D6
  #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 #xCA62C1D6 #xCA62C1D6))


;;;
;;; *sha1-h*
;;; (See FIPS PUB 180-2 section 5.3, "Setting the Initial Hash Value").
;;; These are the five 32-bit integers of the 160-bit SHA-1 hash value.
;;; They must be initialized before the first message block is processed.
;;; (See sha1-reset for the initial values).
;;; They are recomputed each time a message block is processed.
;;;

(defparameter *sha1-h* (list 0 0 0 0 0))


;;;
;;; *sha1-n*
;;; This integer keeps a running count of the message bits for the SHA-1 hash.
;;; It eventually comprises the last 64 bits of a padded message.
;;;

(defparameter *sha1-n* 0)


;;;
;;; *sha1-q*
;;; is the list of bytes in the SHA-1 message bit queue.
;;; The SHA-1 message bit queue is implemented as a list of bytes and a binary string.
;;; This structure allows message bits to be appended to the queue
;;; either in the form of 8-bit integers, or as a binary string.
;;; The bytes at the front of *sha1-q* are the oldest bytes.
;;; The most-significant bits in a byte are the oldest bits.
;;;

(defparameter *sha1-q* nil)


;;;
;;; *sha1-r*
;;; is the binary string in the SHA-1 message bit queue.
;;; The binary string *sha1-r* contains ASCII 1's and 0's.
;;; These bits are considered the newest bits in the queue
;;; and are tranferred to the list of bytes by sha1-proc.
;;;

(defparameter *sha1-r* "")


;;;
;;; sha1-qlen
;;; returns the total number of bits in the SHA-1 queue. 
;;;

(defun sha1-qlen ()
  (+ (* 8 (length *sha1-q*)) (length *sha1-r*)))


;;;
;;; sha1-f
;;; takes a time-slot integer i and three 32-bit integers x y z
;;; and returns the function value.
;;;

(defun sha1-f (i x y z)
  (if (or (< i 0) (< 79 i)) (error "i must be in [0,79]"))
  (if (< i 20) (return-from sha1-f (sha-ch-32 x y z)))
  (if (< i 40) (return-from sha1-f (sha-parity-32 x y z)))
  (if (< i 60) (return-from sha1-f (sha-maj-32 x y z)))
  (return-from sha1-f (sha-parity-32 x y z)))


;;;
;;; sha1-calc
;;; (See FIPS 180-2 section 6.1.2).
;;; sha1-calc is the core SHA-1 algorithm.  It is called by sha1-proc.
;;; It takes a list m of 64 8-bit integers and calculates the SHA-1 hash.
;;; The index i is used instead of t, because t is a reserved symbol in Lisp.
;;;

(defun sha1-calc (m)

  ;; Make sure that the input m is valid.
  (if (not (blistp m)) (error "m must be a list of bytes"))
  (if (/= 64 (length m)) (error "list m must have exactly 64 bytes"))

  ;; Declare the local variables.
  (let ((w) (a) (b) (c) (d) (e) (x))

    ;; Simple vector array w contains eighty 32-bit integer registers.
    (setf w (make-array 80))

    ;; Init the five working vars with the old hash value.
    (setf a (nth 0 *sha1-h*))
    (setf b (nth 1 *sha1-h*))
    (setf c (nth 2 *sha1-h*))
    (setf d (nth 3 *sha1-h*))
    (setf e (nth 4 *sha1-h*))

    ;; Parse m into the first sixteen w registers.
    (dotimes (i 16)
      (setf (svref w i) (+ (* (pop m) #x1000000)
			   (* (pop m) #x10000)
			   (* (pop m) #x100)
			   (pop m))))

    ;; Prepare the message schedule.
    (do ((i 16 (1+ i))) ((> i 79))
	(setf (svref w i)
	      (sha-ROTL 1 (logxor
			    (svref w (- i 3))
			    (svref w (- i 8))
			    (svref w (- i 14))
			    (svref w (- i 16))))))

    ;; For t = 0 to 79:
    (dotimes (i 80) 
      (setf x (mod (+ (sha-ROTL 5 a)
			 (sha1-f i b c d)
			 e
			 (svref *sha1-k* i)
			 (svref w i))
		      #x100000000))
      (setf e d)
      (setf d c)
      (setf c (sha-ROTL 30 b))
      (setf b a)
      (setf a x)
      )

    ;; Compute the intermediate hash value.
    (setf (nth 0 *sha1-h*) (mod (+ a (nth 0 *sha1-h*)) #x100000000))
    (setf (nth 1 *sha1-h*) (mod (+ b (nth 1 *sha1-h*)) #x100000000))
    (setf (nth 2 *sha1-h*) (mod (+ c (nth 2 *sha1-h*)) #x100000000))
    (setf (nth 3 *sha1-h*) (mod (+ d (nth 3 *sha1-h*)) #x100000000))
    (setf (nth 4 *sha1-h*) (mod (+ e (nth 4 *sha1-h*)) #x100000000)))
  nil)



;;;
;;; sha1-proc
;;; Called by sha1-bits, sha1-bytes, and sha1-hash.
;;; Provides control over the sha1-calc function.
;;; Returns nil in all cases.
;;;

(defun sha1-proc ()

  ;; Return if the queue has less than 512 bits.
  (if (< (sha1-qlen) 512) (return-from sha1-proc nil))

  ;; Move all excess bits in *sha1-r* to *sha1-q*.
  (while (> (length *sha1-r*) 7)
    (setf *sha1-q* (append *sha1-q* (list (bin-int (subseq *sha1-r* 0 8)))))
    (setf *sha1-r* (subseq *sha1-r* 8 (length *sha1-r*))))

  ;; Process each 512-bit message block in *sha1-q*.
  (while (> (sha1-qlen) 511)
    (sha1-calc (subseq *sha1-q* 0 64))
    (setf *sha1-q* (subseq *sha1-q* 64 (length *sha1-q*))))

  nil)


;;;
;;; sha1-reset
;;; initializes the value in sha1-h,
;;; initializes the bit queue to 0, and
;;; initializes the bit counter sha1-n to 0.
;;; (See FIPS PUB 180-2 section 5.3.1).
;;;

(defun sha1-reset ()
  (setf (nth 0 *sha1-h*) #x67452301)
  (setf (nth 1 *sha1-h*) #xEFCDAB89)
  (setf (nth 2 *sha1-h*) #x98BADCFE)
  (setf (nth 3 *sha1-h*) #x10325476)
  (setf (nth 4 *sha1-h*) #xC3D2E1F0)
  (setf *sha1-q* nil)
  (setf *sha1-r* "")
  (setf *sha1-n* 0))


;;;
;;; sha1-bits
;;; appends bits onto the end of the queue.
;;; The input x is a binary string (ASCII 1's and 0's).
;;; Calls sha1-proc to process any message blocks.
;;; Returns the number of message bits processed so far.
;;;

(defun sha1-bits (x)

  ;; Make sure that x is a binary string.
  (if (not (bin-stringp x)) (error "x must be a binary string"))

  ;; Tack x onto the end of *sha1-r*.
  (setf *sha1-r* (format nil "~A~A" *sha1-r* x))

  ;; Process the bits in the queue.
  (sha1-proc)

  ;; Update the total number of message bits.
  (incf *sha1-n* (length x)))


;;;
;;; sha1-bytes
;;; appends bytes onto the end of the queue.
;;; The input b is a list of bytes.
;;; Calls sha1-proc to process any message blocks.
;;; Returns the number of message bits processed so far.
;;;

(defun sha1-bytes (b)

  ;; Make sure that b is a list of bytes.
  (if (not (blistp b)) (error "b must be a list of bytes"))

  ;; Tack b onto the end of *sha1-q*.
  (setf *sha1-q* (append *sha1-q* b))

  ;; Process the bits in the queue.
  (sha1-proc)

  ;; Update the total number of message bits.
  (incf *sha1-n* (* 8 (length b))))


;;;
;;; sha1-hash
;;; returns the final hash value.  It takes no arguments.
;;; Instead, it inserts the correct number of padding bits
;;; and the 64-bit total number of message bits, calls sha1-proc,
;;; and finally prints the hash value.
;;; See FIPS PUB 180-2 section 5.1.1.
;;;

(defun sha1-hash ()

  ;; Make sure that the queue is ready.
  (if (> (sha1-qlen) 511) (error "sha1 queue has too many elements"))

  ;; Append k+1 padding bits to the end of *sha1-r*.
  (let ((n) (k) (f) (x))
    (setf n (sha1-qlen))
    (setf k (if (< n 448) (- 447 n) (- 959 n)))
    (setf f (format nil "~A~A,'0B" "1~" k)) ; f is a format string
    (setf x (format nil f 0))
    (setf *sha1-r* (format nil "~A~A" *sha1-r* x)))

  ;; Append the 64-bit count to the end of *sha1-r*.
  (setf *sha1-r* (format nil "~A~64,'0B" *sha1-r* *sha1-n*))

  ;; Process the bits in the queue.
  (sha1-proc)

  ;; Print the final hash value.
  (+ (* (nth 0 *sha1-h*) (expt 2 (* 32 4)))
     (* (nth 1 *sha1-h*) (expt 2 (* 32 3)))
     (* (nth 2 *sha1-h*) (expt 2 (* 32 2)))
     (* (nth 3 *sha1-h*) (expt 2 (* 32 1)))
     (nth 4 *sha1-h*)))


;;;;
;;;; Blacklight OpenPGP code for SHA-256
;;;; structures: *sha256-k* *sha256-h* *sha256-n* *sha256-q* *sha256-r*
;;;; functions: sha256-qlen sha256-bs0 sha256-bs1 sha256-ls0 sha256-ls1
;;;;            sha256-calc sha256-proc 
;;;;            sha256-reset sha256-bits sha256-bytes sha256-hash
;;;;


;;;
;;; *sha256-k*
;;; (See FIPS PUB 180-2 section 4.2.2, "SHA-256 Constants").
;;; SHA-256 uses a sequence of sixty-four constant 32-bit words
;;; $K^{(256)}_0, K^{(256)}_1, \ldots, K^{(256)}_63$.
;;; These words represent the first thirty-two bits of the fractional parts 
;;; of the cube roots of the first sixty-four prime numbers.
;;; We represent these in a vector in order to speed up access.
;;; Use the svref operator to access vector elements.
;;;

(defconstant *sha256-k* (vector
  #x428A2F98 #x71374491 #xB5C0FBCF #xE9B5DBA5 #x3956C25B #x59F111F1 #x923F82A4 #xAB1C5ED5 
  #xD807AA98 #x12835B01 #x243185BE #x550C7DC3 #x72BE5D74 #x80DEB1FE #x9BDC06A7 #xC19BF174 
  #xE49B69C1 #xEFBE4786 #x0FC19DC6 #x240CA1CC #x2DE92C6F #x4A7484AA #x5CB0A9DC #x76F988DA 
  #x983E5152 #xA831C66D #xB00327C8 #xBF597FC7 #xC6E00BF3 #xD5A79147 #x06CA6351 #x14292967 
  #x27B70A85 #x2E1B2138 #x4D2C6DFC #x53380D13 #x650A7354 #x766A0ABB #x81C2C92E #x92722C85 
  #xA2BFE8A1 #xA81A664B #xC24B8B70 #xC76C51A3 #xD192E819 #xD6990624 #xF40E3585 #x106AA070 
  #x19A4C116 #x1E376C08 #x2748774C #x34B0BCB5 #x391C0CB3 #x4ED8AA4A #x5B9CCA4F #x682E6FF3 
  #x748F82EE #x78A5636F #x84C87814 #x8CC70208 #x90BEFFFA #xA4506CEB #xBEF9A3F7 #xC67178F2))


;;;
;;; *sha256-h*
;;; These are the eight 32-bit integers of the 256-bit SHA-256 hash value.
;;; They must be initialized before the first message block is processed.
;;; (See sha256-reset for the initial values).
;;; They are recomputed each time a message block is processed.
;;;

(defparameter *sha256-h* (vector 0 0 0 0 0 0 0 0))


;;;
;;; *sha256-n*
;;; This integer keeps a running count of the message bits for the SHA-256 hash.
;;; It eventually comprises the last 64 bits of a padded message.
;;;

(defparameter *sha256-n* 0)


;;;
;;; *sha256-q*
;;; is the list of bytes in the SHA-256 message bit queue.
;;; The SHA-256 message bit queue is implemented as a list of bytes and a binary string.
;;; This structure allows message bits to be appended to the queue
;;; either in the form of 8-bit integers, or as a binary string.
;;; The bytes at the front of *sha256-q* are the oldest bytes.
;;; The most-significant bits in a byte are the oldest bits.
;;;

(defparameter *sha256-q* nil)


;;;
;;; *sha256-r*
;;; is the binary string in the SHA-256 message bit queue.
;;; The binary string *sha256-r* contains ASCII 1's and 0's.
;;; These bits are considered the newest bits in the queue
;;; and are tranferred to the list of bytes by sha256-proc.
;;;

(defparameter *sha256-r* "")


;;;
;;; sha256-qlen
;;; returns the total number of bits in the SHA-256 queue. 
;;;

(defun sha256-qlen ()
  (+ (* 8 (length *sha256-q*)) (length *sha256-r*)))


;;;;
;;;; SHA-256 sigma functions
;;;; (See FIPS PUB 180-2 section 4.1.2).
;;;; SHA-256 uses the four sigma functions 
;;;; $\Sigma^{256}_0$, $\Sigma^{256}_1$, $\sigma^{256}_0$, $\sigma^{256}_1$.
;;;; Each operates on the single 32-bit word x and produces a 32-bit word as output.
;;;;


;;;
;;; sha256-bs0  (Big Sigma 0)
;;;

(defun sha256-bs0 (x)
  (logxor (sha-ROTR 2 x) (sha-ROTR 13 x) (sha-ROTR 22 x)))


;;;
;;; sha256-bs1  (Big Sigma 1)
;;;

(defun sha256-bs1 (x)
  (logxor (sha-ROTR 6 x) (sha-ROTR 11 x) (sha-ROTR 25 x)))


;;;
;;; sha256-ls0  (Little Sigma 0)
;;;

(defun sha256-ls0 (x)
  (logxor (sha-ROTR 7 x) (sha-ROTR 18 x) (sha-SHR 3 x)))


;;;
;;; sha256-ls1  (Little Sigma 1)
;;;

(defun sha256-ls1 (x)
  (logxor (sha-ROTR 17 x) (sha-ROTR 19 x) (sha-SHR 10 x)))


;;;
;;; sha256-calc
;;; (See FIPS 180-2 section 6.2.2).
;;; sha256-calc is the core of our SHA-256 implementation. Called by sha256-proc,
;;; it takes a list m of 64 8-bit integers and calculates the SHA-256 hash.
;;; The index i is used instead of t, because t is a reserved symbol in Lisp.
;;;

(defun sha256-calc (m)

  ;; Make sure that m is a list of 64 bytes.
  (if (not (and (blistp m) (= 64 (length m))))
      (error "m must be a list of 64 bytes"))

  ;; Declare the local variables.
  (let ((a) (b) (c) (d) (e) (f) (g) (h)
	(x1) (x2)
	(w (make-array 64)))

    ;; Prepare the message schedule.
    (dotimes (i 16)
      (setf (svref w i) (+ (ash (pop m) 24)
			   (ash (pop m) 16)
			   (ash (pop m) 8)
			   (pop m))))
    (do ((i 16 (1+ i))) ((> i 63))
	(setf (svref w i)
	      (logand (+ (sha256-ls1 (svref w (- i 2)))
		      (svref w (- i 7))
		      (sha256-ls0 (svref w (- i 15)))
		      (svref w (- i 16)))
		      #xFFFFFFFF)))

    ;; Initialize the eight working variables.
    (setf a (svref *sha256-h* 0))
    (setf b (svref *sha256-h* 1))
    (setf c (svref *sha256-h* 2))
    (setf d (svref *sha256-h* 3))
    (setf e (svref *sha256-h* 4))
    (setf f (svref *sha256-h* 5))
    (setf g (svref *sha256-h* 6))
    (setf h (svref *sha256-h* 7))

    ;; For t = 0 to 63:
    (dotimes (i 64) 
      (setf x1 (logand (+ h
		       (sha256-bs1 e)
		       (sha-ch-32 e f g)
		       (svref *sha256-k* i)
		       (svref w i))
		       #xFFFFFFFF))
      (setf x2 (logand (+ (sha256-bs0 a)
		       (sha-maj-32 a b c))
		       #xFFFFFFFF))
      (setf h g)
      (setf g f)
      (setf f e)
      (setf e (logand (+ d x1) #xFFFFFFFF))
      (setf d c)
      (setf c b)
      (setf b a)
      (setf a (logand (+ x1 x2) #xFFFFFFFF)))

    ;; Compute the ith intermediate hash value.
    (setf (svref *sha256-h* 0) (logand (+ a (svref *sha256-h* 0)) #xFFFFFFFF))
    (setf (svref *sha256-h* 1) (logand (+ b (svref *sha256-h* 1)) #xFFFFFFFF))
    (setf (svref *sha256-h* 2) (logand (+ c (svref *sha256-h* 2)) #xFFFFFFFF))
    (setf (svref *sha256-h* 3) (logand (+ d (svref *sha256-h* 3)) #xFFFFFFFF))
    (setf (svref *sha256-h* 4) (logand (+ e (svref *sha256-h* 4)) #xFFFFFFFF))
    (setf (svref *sha256-h* 5) (logand (+ f (svref *sha256-h* 5)) #xFFFFFFFF))
    (setf (svref *sha256-h* 6) (logand (+ g (svref *sha256-h* 6)) #xFFFFFFFF))
    (setf (svref *sha256-h* 7) (logand (+ h (svref *sha256-h* 7)) #xFFFFFFFF)))

  nil)


;;;
;;; sha256-proc
;;; Called by sha256-bits, sha256-bytes, and sha256-hash.
;;; Provides control over the sha256-calc function.
;;; Returns nil in all cases.
;;;

(defun sha256-proc ()

  ;; Return if the queue has less than 512 bits.
  (if (< (sha256-qlen) 512) (return-from sha256-proc nil))

  ;; Move all excess bits in *sha256-r* to *sha256-q*.
  (while (> (length *sha256-r*) 7)
    (setf *sha256-q* (append *sha256-q* (list (bin-int (subseq *sha256-r* 0 8)))))
    (setf *sha256-r* (subseq *sha256-r* 8 (length *sha256-r*))))

  ;; Process each 512-bit message block in *sha256-q*.
  (while (> (sha256-qlen) 511)
    (let ((b nil))
      (dotimes (i 64) (push (pop *sha256-q*) b))
      (sha256-calc (reverse b))))

  nil)


;;;
;;; sha256-reset
;;;

(defun sha256-reset ()
  (setf (svref *sha256-h* 0) #x6A09E667)
  (setf (svref *sha256-h* 1) #xBB67AE85)
  (setf (svref *sha256-h* 2) #x3C6EF372)
  (setf (svref *sha256-h* 3) #xA54FF53A)
  (setf (svref *sha256-h* 4) #x510E527F)
  (setf (svref *sha256-h* 5) #x9B05688C)
  (setf (svref *sha256-h* 6) #x1F83D9AB)
  (setf (svref *sha256-h* 7) #x5BE0CD19)
  (setf *sha256-q* nil)
  (setf *sha256-r* "")
  (setf *sha256-n* 0))


;;;
;;; sha256-bits
;;; appends bits onto the end of the queue.
;;; The input x is a binary string (ASCII 1's and 0's).
;;; Calls sha256-proc to process any message blocks.
;;; Returns the number of message bits processed so far.
;;;

(defun sha256-bits (x)

  ;; Make sure that x is a binary string.
  (if (not (bin-stringp x)) (error "x must be a binary string"))

  ;; Tack x onto the end of *sha256-r*.
  (setf *sha256-r* (format nil "~A~A" *sha256-r* x))

  ;; Process the bits in the queue.
  (sha256-proc)

  ;; Update the total number of message bits.
  (incf *sha256-n* (length x)))


;;;
;;; sha256-bytes
;;; appends bytes onto the end of the queue.
;;; The input b is a list of bytes.
;;; Calls sha256-proc to process any message blocks.
;;; Returns the number of message bits processed so far.
;;;

(defun sha256-bytes (b)

  ;; Make sure that b is a list of bytes.
  (if (not (blistp b)) (error "b must be a list of bytes"))

  ;; Tack b onto the end of *sha256-q*.
  (setf *sha256-q* (append *sha256-q* b))

  ;; Process the bits in the queue.
  (sha256-proc)

  ;; Update the total number of message bits.
  (incf *sha256-n* (* 8 (length b))))


;;;
;;; sha256-hash
;;; returns the final hash value.  It takes no arguments.
;;; Instead, it inserts the correct number of padding bits
;;; and the 64-bit total number of message bits, calls sha256-proc,
;;; and finally prints the hash value.
;;; See FIPS PUB 180-2 section 5.1.1.
;;;

(defun sha256-hash ()

  ;; Make sure that the queue is ready.
  (if (> (sha256-qlen) 511) (error "sha1 queue has too many elements"))

  ;; Append k+1 padding bits to the end of *sha256-r*.
  (let ((n) (k) (f) (x))
    (setf n (sha256-qlen))
    (setf k (if (< n 448) (- 447 n) (- 959 n)))
    (setf f (format nil "~A~A,'0B" "1~" k)) ; f is a format string
    (setf x (format nil f 0))
    (setf *sha256-r* (format nil "~A~A" *sha256-r* x)))

  ;; Append the 64-bit count to the end of *sha256-r*.
  (setf *sha256-r* (format nil "~A~64,'0B" *sha256-r* *sha256-n*))

  ;; Process the bits in the queue.
  (sha256-proc)

  ;; Print the final hash value.
  (+ (* (svref *sha256-h* 0) (expt 2 (* 32 7)))
     (* (svref *sha256-h* 1) (expt 2 (* 32 6)))
     (* (svref *sha256-h* 2) (expt 2 (* 32 5)))
     (* (svref *sha256-h* 3) (expt 2 (* 32 4)))
     (* (svref *sha256-h* 4) (expt 2 (* 32 3)))
     (* (svref *sha256-h* 5) (expt 2 (* 32 2)))
     (* (svref *sha256-h* 6) (expt 2 (* 32 1)))
     (svref *sha256-h* 7)))



;;;
;;; FAST FAST FAST FAST FAST FAST FAST FAST 
;;; FAST FAST FAST FAST FAST FAST FAST FAST 
;;; FAST FAST FAST FAST FAST FAST FAST FAST 
;;; FAST FAST FAST FAST FAST FAST FAST FAST 
;;; FAST FAST FAST FAST FAST FAST FAST FAST 
;;;
;;; Fast SHA-256 implemented with sha256.dylib.
;;; old structures: *sha256-n* *sha256-q* *sha256-r*
;;; new structures: *sha256-fast-H* *sha256-fast-W*
;;; old functions: sha256-qlen sha256-bs0 sha256-bs1 sha256-ls0 sha256-ls1
;;; new functions: sha256-fast-calc sha256-fast-proc sha256-fast-reset
;;;                sha256-fast-bits sha256-fast-bytes sha256-fast-hash
;;;
;;; To open sha256.dylib:
;;; ? (open-shared-library "../SHA/sha256.dylib")
;;; To check that the sha256_calc function is there:
;;; ? (external "_sha256_calc")
;;;


;;;
;;; *sha256-fast-H*
;;; This 8 by 32-bit word block is specified in section 5.3.2.
;;; It is declared in sha.lisp by sha256-fast-malloc.
;;; A pointer to this block is passed to the C function sha256_calc.
;;;

(defparameter *sha256-fast-H* nil)
(defparameter *sha256-fast-H-ptr* nil)

;;;
;;; *sha256-fast-W*
;;; This 64-word message schedule is specified in section 6.2.
;;; It is declared in sha.lisp by sha256-fast-malloc.
;;; A pointer to this block is passed to the C function sha256_calc.
;;;

(defparameter *sha256-fast-W* nil)
(defparameter *sha256-fast-W-ptr* nil)


;;;
;;; sha256-fast-reset
;;;

(defun sha256-fast-reset ()

  ;; Open the shared library.
  (open-shared-library "../SHA/sha256.dylib")

  ;; Reserve memory from the heap.
  (multiple-value-bind (hd hp)
    (make-heap-ivector 8 '(unsigned-byte 32))
    (setq *sha256-fast-H* hd)
    (setq *sha256-fast-H-ptr* hp))
  (multiple-value-bind (wd wp)
    (make-heap-ivector 64 '(unsigned-byte 32))
    (setq *sha256-fast-W* wd)
    (setq *sha256-fast-W-ptr* wp))

  ;; Initialize the hash value.
  (setf (aref *sha256-fast-H* 0) #x6A09E667)
  (setf (aref *sha256-fast-H* 1) #xBB67AE85)
  (setf (aref *sha256-fast-H* 2) #x3C6EF372)
  (setf (aref *sha256-fast-H* 3) #xA54FF53A)
  (setf (aref *sha256-fast-H* 4) #x510E527F)
  (setf (aref *sha256-fast-H* 5) #x9B05688C)
  (setf (aref *sha256-fast-H* 6) #x1F83D9AB)
  (setf (aref *sha256-fast-H* 7) #x5BE0CD19)

  ;; Initialize the message schedule.
  (dotimes (i 64)
    (setf (aref *sha256-fast-W* i) 0))

  ;; Set up the queue.
  (setf *sha256-q* nil)
  (setf *sha256-r* "")
  (setf *sha256-n* 0))


;;;
;;; sha256-fast-calc
;;; This function is the core of our fast SHA-256 implementation.
;;; It is called by sha256-fast-proc.
;;; It takes a list of 64 bytes and copies them into *sha256-fast-W*,
;;; then calls the C function "sha256_calc" via sha256.dylib.
;;;

(defun sha256-fast-calc (m)

  ;; Make sure that m is a list of 64 bytes.
  (if (not (and (blistp m) (= 64 (length m))))
      (error "m must be a list of 64 bytes"))


  ;; Declare local variables.
  (let ((err))

    ;; Copy 64 bytes in m into 16 words in *sha256-W*.
    (dotimes (i 16)
      (setf (aref *sha256-fast-W* i) (+ (ash (pop m) 24)
					(ash (pop m) 16)
					(ash (pop m) 8)
					(pop m))))

      ;; Invoke sha256_calc.
      (setf err (external-call "_sha256_calc"
			       :address *sha256-fast-H-ptr*
			       :address *sha256-fast-W-ptr*
			       :unsigned-int))

      ;; Check for errors.
      (if (not (= 0 err))
	  (error "sha256_calc returned ~A" err))

      nil))


;;;
;;; sha256-fast-proc
;;; Called by sha256-fast-bits, sha256-fast-bytes, and sha256-fast-hash.
;;; Provides control over the sha256-fast-calc function.
;;; Returns nil in all cases.
;;;

(defun sha256-fast-proc ()

  ;; Return if the queue has less than 512 bits.
  (if (< (sha256-qlen) 512) (return-from sha256-fast-proc nil))

  ;; Move all excess bits in *sha256-r* to *sha256-q*.
  (while (> (length *sha256-r*) 7)
    (setf *sha256-q* (append *sha256-q* (list (bin-int (subseq *sha256-r* 0 8)))))
    (setf *sha256-r* (subseq *sha256-r* 8 (length *sha256-r*))))

  ;; Process each 512-bit message block in *sha256-q*.
  (while (> (sha256-qlen) 511)
    (let ((b nil))
      (dotimes (i 64) (push (pop *sha256-q*) b))
      (sha256-fast-calc (reverse b))))

  nil)


;;;
;;; sha256-fast-bits
;;; appends bits onto the end of the queue.
;;; The input x is a binary string (ASCII 1's and 0's).
;;; Calls sha256-fast-proc to process any message blocks.
;;; Returns the number of message bits processed so far.
;;;

(defun sha256-fast-bits (x)

  ;; Make sure that x is a binary string.
  (if (not (bin-stringp x)) (error "x must be a binary string"))

  ;; Tack x onto the end of *sha256-r*.
  (setf *sha256-r* (format nil "~A~A" *sha256-r* x))

  ;; Process the bits in the queue.
  (sha256-fast-proc)

  ;; Update the total number of message bits.
  (incf *sha256-n* (length x)))


;;;
;;; sha256-fast-bytes
;;; appends bytes onto the end of the queue.
;;; The input b is a list of bytes.
;;; Calls sha256-fast-proc to process any message blocks.
;;; Returns the number of message bits processed so far.
;;;

(defun sha256-fast-bytes (b)

  ;; Make sure that b is a list of bytes.
  (if (not (blistp b)) (error "b must be a list of bytes"))

  ;; Tack b onto the end of *sha256-q*.
  (setf *sha256-q* (append *sha256-q* b))

  ;; Process the bits in the queue.
  (sha256-fast-proc)

  ;; Update the total number of message bits.
  (incf *sha256-n* (* 8 (length b))))


;;;
;;; sha256-fast-hash
;;; returns the final hash value.  It takes no arguments.
;;; Instead, it inserts the correct number of padding bits
;;; and the 64-bit total number of message bits, calls sha256-fast-proc,
;;; and finally prints the hash value.
;;; See FIPS PUB 180-2 section 5.1.1.
;;;

(defun sha256-fast-hash ()

  ;; Make sure that the queue is ready.
  (if (> (sha256-qlen) 511) (error "sha1 queue has too many elements"))

  ;; Declare local variables.
  (let ((n) (k) (f) (x) (h))

    ;; Append k+1 padding bits to the end of *sha256-r*.
    (setf n (sha256-qlen))
    (setf k (if (< n 448) (- 447 n) (- 959 n)))
    (setf f (format nil "~A~A,'0B" "1~" k)) ; f is a format string
    (setf x (format nil f 0))
    (setf *sha256-r* (format nil "~A~A" *sha256-r* x))

    ;; Append the 64-bit count to the end of *sha256-r*.
    (setf *sha256-r* (format nil "~A~64,'0B" *sha256-r* *sha256-n*))

    ;; Process the bits in the queue.
    (sha256-fast-proc)

    ;; Calculate the final hash value.
    (setf h (+ (* (aref *sha256-fast-H* 0) (expt 2 (* 32 7)))
	       (* (aref *sha256-fast-H* 1) (expt 2 (* 32 6)))
	       (* (aref *sha256-fast-H* 2) (expt 2 (* 32 5)))
	       (* (aref *sha256-fast-H* 3) (expt 2 (* 32 4)))
	       (* (aref *sha256-fast-H* 4) (expt 2 (* 32 3)))
	       (* (aref *sha256-fast-H* 5) (expt 2 (* 32 2)))
	       (* (aref *sha256-fast-H* 6) (expt 2 (* 32 1)))
	       (aref *sha256-fast-H* 7)))

    ;; Free the memory from the heap.
    (dispose-heap-ivector *sha256-fast-H*)
    (dispose-heap-ivector *sha256-fast-W*)

    ;; Return the final hash value.
    h))



;;;;
;;;; SYSTEM LEVEL FUNCTIONS
;;;;


;;;
;;; sha1-file
;;; computes the SHA-1 hash of the file given by the filename f.
;;;

(defun sha1-file (f)
  (sha1-reset)
  (sha1-bytes (getfile f))
  (format nil "~40,'0X" (sha1-hash)))


;;;
;;; sha256-file
;;; computes the SHA-256 hash of the file given by the filename f.
;;;

(defun sha256-file (f)
  (sha256-reset)
  (sha256-bytes (getfile f))
  (format nil "~64,'0X" (sha256-hash)))


;;;
;;; v4-fingerprint
;;; takes a parsed Public Key packet or a parsed Public Subkey packet,
;;; replaces field 0 with PUBLIC-KEY-PACKET,
;;; replaces field 1 with OLD-HEADER-3,
;;; replaces field 4 with RSA-ENCR-SIGN,
;;; builds the list of packet bytes, computes the SHA-1 hash across the entire list,
;;; and returns the result, a 160-bit integer.
;;; The V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
;;; followed by the two-octet packet length, followed by the entire
;;; public key packet (C6-packet) starting with the version field.  
;;;

(defun v4-fingerprint (p)
  (let ((q (copy-list p)))
    (setf (nth 0 q) 'PUBLIC-KEY-PACKET)
    (setf (nth 1 q) 'OLD-HEADER-3)
    (setf (nth 4 q) 'RSA-ENCR-SIGN)
    (sha1-reset)
    (sha1-bytes (build-packet q))
    (sha1-hash)))


;;;
;;; padded-SHA256-hash-p
;;; returns T iff ph is a properly padded SHA-256 hash.
;;;

(defun padded-SHA256-hash-p (ph)
  (let ((b) (n))
    (setf b (split-int (1+ (nbytes ph)) ph))
    (setf n (length b))
    (and (= 0 (nth 0 b))
	 (= 1 (nth 1 b))
	 (= 0 (nth (- n 19 32 1) b))
	 (equal (hash-prefix 'SHA-256)
		(subseq b (- n 19 32) (- n 32))))))


;;;
;;; sha-okayp
;;; does a bunch of tests from FIPS 180-2
;;; for SHA-1 and SHA-256.
;;;

(defun sha-okayp ()

  ;; FIPS 180-2 A.1 test with bits
  (sha1-reset)
  (sha1-bits (text-bin "abc"))
  (if (/= (sha1-hash)
	  #xA9993E364706816ABA3E25717850C26C9CD0D89D)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 A.1 test with bytes
  (sha1-reset)
  (sha1-bytes (split-str "abc"))
  (if (/= (sha1-hash)
	  #xA9993E364706816ABA3E25717850C26C9CD0D89D)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 A.2 test with bits
  (sha1-reset)
  (sha1-bits (text-bin "abcdbcdecdefdefgefghfghighij"))
  (sha1-bits (text-bin "hijkijkljklmklmnlmnomnopnopq"))
  (if (/= (sha1-hash)
	  #x84983E441C3BD26EBAAE4AA1F95129E5E54670F1)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 A.2 test with bytes
  (sha1-reset)
  (sha1-bytes (split-str "abcdbcdecdefdefgefghfghighij"))
  (sha1-bytes (split-str "hijkijkljklmklmnlmnomnopnopq"))
  (if (/= (sha1-hash)
	  #x84983E441C3BD26EBAAE4AA1F95129E5E54670F1)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 B.1 test with bits
  (sha256-reset)
  (sha256-bits (text-bin "abc"))
  (if (/= (sha256-hash)
	  #xBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 B.1 test with bytes
  (sha256-reset)
  (sha256-bytes (split-str "abc"))
  (if (/= (sha256-hash)
	  #xBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 B.2 test with bits
  (sha256-reset)
  (sha256-bits (text-bin "abcdbcdecdefdefgefghfghighij"))
  (sha256-bits (text-bin "hijkijkljklmklmnlmnomnopnopq"))
  (if (/= (sha256-hash)
	  #x248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 B.2 test with bytes
  (sha256-reset)
  (sha256-bytes (split-str "abcdbcdecdefdefgefghfghighij"))
  (sha256-bytes (split-str "hijkijkljklmklmnlmnomnopnopq"))
  (if (/= (sha256-hash)
	  #x248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 B.1 test with bits
  (sha256-fast-reset)
  (sha256-fast-bits (text-bin "abc"))
  (if (/= (sha256-fast-hash)
	  #xBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 B.1 test with bytes
  (sha256-fast-reset)
  (sha256-fast-bytes (split-str "abc"))
  (if (/= (sha256-fast-hash)
	  #xBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 B.2 test with bits
  (sha256-fast-reset)
  (sha256-fast-bits (text-bin "abcdbcdecdefdefgefghfghighij"))
  (sha256-fast-bits (text-bin "hijkijkljklmklmnlmnomnopnopq"))
  (if (/= (sha256-fast-hash)
	  #x248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1)
      (return-from sha-okayp nil))

  ;; FIPS 180-2 B.2 test with bytes
  (sha256-fast-reset)
  (sha256-fast-bytes (split-str "abcdbcdecdefdefgefghfghighij"))
  (sha256-fast-bytes (split-str "hijkijkljklmklmnlmnomnopnopq"))
  (if (/= (sha256-fast-hash)
	  #x248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1)
      (return-from sha-okayp nil))

  T)


