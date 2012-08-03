;;;; BlackLight/OpenPGP/aes.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; This file contains Common Lisp expressions that implement 
;;;; the Advanced Encryption Standard (AES) specified in FIPS 197.
;;;; "The AES algorithm is a symmetric block cipher that can 
;;;; encrypt (encipher) and decrypt (decipher) information."
;;;;


;;;
;;; aes-sbox
;;; This is a table of 256 bytes.
;;; These values are substituted for other values.
;;; This table is used by aes-subword and aes-sub-bytes.
;;;

(defconstant aes-sbox
  (vector 
   #x63 #x7C #x77 #x7B #xF2 #x6B #x6F #xC5 #x30 #x01 #x67 #x2B #xFE #xD7 #xAB #x76
   #xCA #x82 #xC9 #x7D #xFA #x59 #x47 #xF0 #xAD #xD4 #xA2 #xAF #x9C #xA4 #x72 #xC0
   #xB7 #xFD #x93 #x26 #x36 #x3F #xF7 #xCC #x34 #xA5 #xE5 #xF1 #x71 #xD8 #x31 #x15
   #x04 #xC7 #x23 #xC3 #x18 #x96 #x05 #x9A #x07 #x12 #x80 #xE2 #xEB #x27 #xB2 #x75
   #x09 #x83 #x2C #x1A #x1B #x6E #x5A #xA0 #x52 #x3B #xD6 #xB3 #x29 #xE3 #x2F #x84
   #x53 #xD1 #x00 #xED #x20 #xFC #xB1 #x5B #x6A #xCB #xBE #x39 #x4A #x4C #x58 #xCF
   #xD0 #xEF #xAA #xFB #x43 #x4D #x33 #x85 #x45 #xF9 #x02 #x7F #x50 #x3C #x9F #xA8
   #x51 #xA3 #x40 #x8F #x92 #x9D #x38 #xF5 #xBC #xB6 #xDA #x21 #x10 #xFF #xF3 #xD2
   #xCD #x0C #x13 #xEC #x5F #x97 #x44 #x17 #xC4 #xA7 #x7E #x3D #x64 #x5D #x19 #x73
   #x60 #x81 #x4F #xDC #x22 #x2A #x90 #x88 #x46 #xEE #xB8 #x14 #xDE #x5E #x0B #xDB
   #xE0 #x32 #x3A #x0A #x49 #x06 #x24 #x5C #xC2 #xD3 #xAC #x62 #x91 #x95 #xE4 #x79
   #xE7 #xC8 #x37 #x6D #x8D #xD5 #x4E #xA9 #x6C #x56 #xF4 #xEA #x65 #x7A #xAE #x08
   #xBA #x78 #x25 #x2E #x1C #xA6 #xB4 #xC6 #xE8 #xDD #x74 #x1F #x4B #xBD #x8B #x8A
   #x70 #x3E #xB5 #x66 #x48 #x03 #xF6 #x0E #x61 #x35 #x57 #xB9 #x86 #xC1 #x1D #x9E
   #xE1 #xF8 #x98 #x11 #x69 #xD9 #x8E #x94 #x9B #x1E #x87 #xE9 #xCE #x55 #x28 #xDF
   #x8C #xA1 #x89 #x0D #xBF #xE6 #x42 #x68 #x41 #x99 #x2D #x0F #xB0 #x54 #xBB #x16))


;;;
;;; aes-table-02
;;; This is a table of 256 pre-computed values.
;;; Each value is the modulo m(x) product of
;;; the index i and the GF(2^8) element {02}.
;;; Ex: {FF} * {02} = {E5}.
;;; See FIPS-197 section 4.2.
;;; This table is used by aes-mix-columns.
;;;

(defconstant aes-table-02
  (vector
   #x00 #x02 #x04 #x06 #x08 #x0A #x0C #x0E #x10 #x12 #x14 #x16 #x18 #x1A #x1C #x1E
   #x20 #x22 #x24 #x26 #x28 #x2A #x2C #x2E #x30 #x32 #x34 #x36 #x38 #x3A #x3C #x3E
   #x40 #x42 #x44 #x46 #x48 #x4A #x4C #x4E #x50 #x52 #x54 #x56 #x58 #x5A #x5C #x5E
   #x60 #x62 #x64 #x66 #x68 #x6A #x6C #x6E #x70 #x72 #x74 #x76 #x78 #x7A #x7C #x7E
   #x80 #x82 #x84 #x86 #x88 #x8A #x8C #x8E #x90 #x92 #x94 #x96 #x98 #x9A #x9C #x9E
   #xA0 #xA2 #xA4 #xA6 #xA8 #xAA #xAC #xAE #xB0 #xB2 #xB4 #xB6 #xB8 #xBA #xBC #xBE
   #xC0 #xC2 #xC4 #xC6 #xC8 #xCA #xCC #xCE #xD0 #xD2 #xD4 #xD6 #xD8 #xDA #xDC #xDE
   #xE0 #xE2 #xE4 #xE6 #xE8 #xEA #xEC #xEE #xF0 #xF2 #xF4 #xF6 #xF8 #xFA #xFC #xFE
   #x1B #x19 #x1F #x1D #x13 #x11 #x17 #x15 #x0B #x09 #x0F #x0D #x03 #x01 #x07 #x05
   #x3B #x39 #x3F #x3D #x33 #x31 #x37 #x35 #x2B #x29 #x2F #x2D #x23 #x21 #x27 #x25
   #x5B #x59 #x5F #x5D #x53 #x51 #x57 #x55 #x4B #x49 #x4F #x4D #x43 #x41 #x47 #x45
   #x7B #x79 #x7F #x7D #x73 #x71 #x77 #x75 #x6B #x69 #x6F #x6D #x63 #x61 #x67 #x65
   #x9B #x99 #x9F #x9D #x93 #x91 #x97 #x95 #x8B #x89 #x8F #x8D #x83 #x81 #x87 #x85
   #xBB #xB9 #xBF #xBD #xB3 #xB1 #xB7 #xB5 #xAB #xA9 #xAF #xAD #xA3 #xA1 #xA7 #xA5
   #xDB #xD9 #xDF #xDD #xD3 #xD1 #xD7 #xD5 #xCB #xC9 #xCF #xCD #xC3 #xC1 #xC7 #xC5
   #xFB #xF9 #xFF #xFD #xF3 #xF1 #xF7 #xF5 #xEB #xE9 #xEF #xED #xE3 #xE1 #xE7 #xE5))


;;;
;;; aes-table-03
;;; This is a table of 256 pre-computed values.
;;; Each value is the modulo m(x) product of
;;; the index i and the GF(2^8) element {03}.
;;; Ex: {FF} * {03} = {1A}.
;;; See FIPS-197 section 4.2.
;;; This table is used by aes-mix-columns.
;;;

(defconstant aes-table-03
  (vector
   #x00 #x03 #x06 #x05 #x0C #x0F #x0A #x09 #x18 #x1B #x1E #x1D #x14 #x17 #x12 #x11
   #x30 #x33 #x36 #x35 #x3C #x3F #x3A #x39 #x28 #x2B #x2E #x2D #x24 #x27 #x22 #x21
   #x60 #x63 #x66 #x65 #x6C #x6F #x6A #x69 #x78 #x7B #x7E #x7D #x74 #x77 #x72 #x71
   #x50 #x53 #x56 #x55 #x5C #x5F #x5A #x59 #x48 #x4B #x4E #x4D #x44 #x47 #x42 #x41
   #xC0 #xC3 #xC6 #xC5 #xCC #xCF #xCA #xC9 #xD8 #xDB #xDE #xDD #xD4 #xD7 #xD2 #xD1
   #xF0 #xF3 #xF6 #xF5 #xFC #xFF #xFA #xF9 #xE8 #xEB #xEE #xED #xE4 #xE7 #xE2 #xE1
   #xA0 #xA3 #xA6 #xA5 #xAC #xAF #xAA #xA9 #xB8 #xBB #xBE #xBD #xB4 #xB7 #xB2 #xB1
   #x90 #x93 #x96 #x95 #x9C #x9F #x9A #x99 #x88 #x8B #x8E #x8D #x84 #x87 #x82 #x81
   #x9B #x98 #x9D #x9E #x97 #x94 #x91 #x92 #x83 #x80 #x85 #x86 #x8F #x8C #x89 #x8A
   #xAB #xA8 #xAD #xAE #xA7 #xA4 #xA1 #xA2 #xB3 #xB0 #xB5 #xB6 #xBF #xBC #xB9 #xBA
   #xFB #xF8 #xFD #xFE #xF7 #xF4 #xF1 #xF2 #xE3 #xE0 #xE5 #xE6 #xEF #xEC #xE9 #xEA
   #xCB #xC8 #xCD #xCE #xC7 #xC4 #xC1 #xC2 #xD3 #xD0 #xD5 #xD6 #xDF #xDC #xD9 #xDA
   #x5B #x58 #x5D #x5E #x57 #x54 #x51 #x52 #x43 #x40 #x45 #x46 #x4F #x4C #x49 #x4A
   #x6B #x68 #x6D #x6E #x67 #x64 #x61 #x62 #x73 #x70 #x75 #x76 #x7F #x7C #x79 #x7A
   #x3B #x38 #x3D #x3E #x37 #x34 #x31 #x32 #x23 #x20 #x25 #x26 #x2F #x2C #x29 #x2A
   #x0B #x08 #x0D #x0E #x07 #x04 #x01 #x02 #x13 #x10 #x15 #x16 #x1F #x1C #x19 #x1A))


;;;
;;; aes-rcon
;;; This is a table of 11 integers.
;;; It is used by aes-expand-128.
;;;

(defconstant aes-rcon
  (vector
   #x00000000
   #x01000000
   #x02000000
   #x04000000
   #x08000000
   #x10000000
   #x20000000
   #x40000000
   #x80000000
   #x1B000000
   #x36000000))


;;;
;;; aes-subword
;;; takes a 32-bit word and, on each of the four bytes,
;;; performs a byte substitution using the aes-sbox table,
;;; where the original byte is the address.
;;; Input is a 32-bit integer.
;;; Output is a 32-bit integer.
;;;

(defun aes-subword (x)
  (let ((b (split-int 4 x)))
    (unite-int (list (svref aes-sbox (nth 0 b))
		     (svref aes-sbox (nth 1 b))
		     (svref aes-sbox (nth 2 b))
		     (svref aes-sbox (nth 3 b))))))


;;;
;;; aes-rotword
;;; takes a 32-bit word and performs a "cyclic permutation."
;;; That is, it rotates everything 8 bits to the left.
;;; Input is a 32-bit integer.
;;; Output is a 32-bit integer.
;;;

(defun aes-rotword (x)
  (logior (logand (* x 256) #xFFFFFF00)
	  (quo x #x1000000)))


;;;
;;; aes-expand-128
;;; takes a 128-bit key integer k
;;; and returns a key-schedule vector w.
;;; The key-schedule consists of forty-four 32-bit words
;;; that are derived from the session key.
;;; This function implements the Key Expansion pseudo code
;;; given in FIPS PUB 197 Figure 11.
;;;

(defun aes-expand-128 (k)
  (let ((b (split-int 16 k))
	(w (make-array 44))
	(temp 0))
    ; Init the first four words of w.
    (setf (svref w 0) (unite-int (subseq b 0 4)))
    (setf (svref w 1) (unite-int (subseq b 4 8)))
    (setf (svref w 2) (unite-int (subseq b 8 12)))
    (setf (svref w 3) (unite-int (subseq b 12 16)))
    ; Calculate the other forty words of w.
    (do ((i 4 (1+ i))) ((= i 44))
	(setf temp (svref w (1- i)))
	(if (= 0 (mod i 4))
	    (setf temp (logxor (aes-subword (aes-rotword temp))
			       (svref aes-rcon (quo i 4)))))
	(setf (svref w i) (logxor (svref w (- i 4)) temp)))
    w))


;;;
;;; aes-print-sched
;;; prints a pretty listing of the key schedule s.
;;;

(defun aes-print-sched (s)
  (dotimes (round 11)
    (format t "~2A ~8,'0X~8,'0X~8,'0X~8,'0X~%" round
	    (aref s (+ 0 (* 4 round)))
	    (aref s (+ 1 (* 4 round)))
	    (aref s (+ 2 (* 4 round)))
	    (aref s (+ 3 (* 4 round))))))


;;;
;;; aes-encode-state
;;; takes a 128-bit integer x and
;;; parses it into the state array s.
;;;

(defun aes-encode-state (s x)
  (let ((b (split-int 16 x)))
    (dotimes (col 4)
      (dotimes (row 4)
	(setf (aref s row col)
	      (pop b))))))


;;;
;;; aes-decode-state
;;; takes a state array s and 
;;; builds a 128-bit integer.
;;;

(defun aes-decode-state (s)
  (let ((b nil))
    (dotimes (col 4)
      (dotimes (row 4)
	(push (aref s row col) b)))
    (unite-int (reverse b))))


;;;
;;; aes-print-state
;;; prints the state in 4x4 hex byte format.
;;;

(defun aes-print-state (s)
  (dotimes (row 4)
    (dotimes (col 4)
      (format t " ~2,'0X" (aref s row col)))
    (format t "~%")))


;;;
;;; aes-sub-bytes
;;; applies the S-Box to each byte of the 16-byte state.
;;; Input is the state, which is updated by this function.
;;;

(defun aes-sub-bytes (s)
  (dotimes (col 4)
    (dotimes (row 4)
      (setf (aref s row col)
	    (aref aes-sbox (aref s row col))))))


;;;
;;; aes-shift-rows
;;; cyclically shifts the last three rows in the state.
;;; Row 0 is left untouched.
;;; Row 1 is shifted one byte to the left.
;;; Row 2 is shifted two bytes to the left.
;;; This is the same as swapping bytes 0 and 2, and 1 and 3.
;;; Row 3 is shifted three bytes to the left.
;;; This is the same as shifting one byte to the right.
;;; Input is the state, which is updated by this function.
;;;

(defun aes-shift-rows (s)
  (let ((temp))
    ;; Row 1
    (setf temp (aref s 1 0))
    (setf (aref s 1 0) (aref s 1 1))
    (setf (aref s 1 1) (aref s 1 2))
    (setf (aref s 1 2) (aref s 1 3))
    (setf (aref s 1 3) temp)
    ;; Row 2
    (setf temp (aref s 2 0))
    (setf (aref s 2 0) (aref s 2 2))
    (setf (aref s 2 2) temp)
    (setf temp (aref s 2 1))
    (setf (aref s 2 1) (aref s 2 3))
    (setf (aref s 2 3) temp)
    ;; Row 3
    (setf temp (aref s 3 3))
    (setf (aref s 3 3) (aref s 3 2))
    (setf (aref s 3 2) (aref s 3 1))
    (setf (aref s 3 1) (aref s 3 0))
    (setf (aref s 3 0) temp)))


;;;
;;; aes-mult-01
;;; returns the product of x times {01}.
;;; Since {01} is the identify element,
;;; this function can be a macro.
;;;

(defun aes-mult-01 (x)
  x)


;;;
;;; aes-mult-02
;;; returns the product of x times {02}.
;;; Does a lookup in a pre-computed vector.
;;;

(defun aes-mult-02 (x)
  (aref aes-table-02 x))


;;;
;;; aes-mult-03
;;; returns the product of x times {03}.
;;; Does a lookup in a pre-computed vector.
;;;

(defun aes-mult-03 (x)
  (aref aes-table-03 x))


;;;
;;; aes-mix-columns
;;; performs the matrix multiplication on each column 
;;; of the state per FIPS-197 equation (5.6).
;;; Input is the state vector.  Uses three functions:
;;; aes-mult-01, aes-mult-02, aes-mult-03 to 
;;; speed things up and keep things simple.
;;;

(defun aes-mix-columns (s)
  (let ((s0) (s1) (s2) (s3))
  (dotimes (c 4)
    (setf s0 (aref s 0 c))
    (setf s1 (aref s 1 c))
    (setf s2 (aref s 2 c))
    (setf s3 (aref s 3 c))
    (setf (aref s 0 c)
	  (logxor (aes-mult-02 s0)
		  (aes-mult-03 s1)
		  (aes-mult-01 s2)
		  (aes-mult-01 s3)))
    (setf (aref s 1 c)
	  (logxor (aes-mult-01 s0)
		  (aes-mult-02 s1)
		  (aes-mult-03 s2)
		  (aes-mult-01 s3)))
    (setf (aref s 2 c)
	  (logxor (aes-mult-01 s0)
		  (aes-mult-01 s1)
		  (aes-mult-02 s2)
		  (aes-mult-03 s3)))
    (setf (aref s 3 c)
	  (logxor (aes-mult-03 s0)
		  (aes-mult-01 s1)
		  (aes-mult-01 s2)
		  (aes-mult-02 s3))))))
	  

;;;
;;; aes-add-round-key
;;; adds a round key to the state by an exclusive-or operation.
;;; Each round key consists of 4 words from the key schedule.
;;; Inputs are the state s and the round r.
;;;

(defun aes-add-round-key (state sched round)
  (let ((state-col) (round-key) (col-bytes))
    (dotimes (col 4)
      (setf state-col
	    (unite-int
	     (list (aref state 0 col)
		   (aref state 1 col)
		   (aref state 2 col)
		   (aref state 3 col))))
      (setf round-key (aref sched (+ col (* 4 round))))
      (setf state-col (logxor state-col round-key))
      (setf col-bytes (split-int 4 state-col))
      (setf (aref state 0 col) (nth 0 col-bytes))
      (setf (aref state 1 col) (nth 1 col-bytes))
      (setf (aref state 2 col) (nth 2 col-bytes))
      (setf (aref state 3 col) (nth 3 col-bytes)))))


;;;
;;; aes-cipher-128
;;; returns ciphertext given key-schedule sched and plaintext p.
;;; sched is a vector of 44 32-bit integers.
;;; The plaintext p and ciphertext are each a 128-bit integer.
;;; This function implements the Cipher pseudo code
;;; given in FIPS PUB 197 Figure 5.
;;;

(defun aes-cipher-128 (sched p)
  (if (not (vectorp sched)) (error "sched must be a vector"))
  (if (not (= 44 (length sched))) (error "sched must have 44 elements"))
  (if (not (integerp p)) (error "p must be an integer"))
;;  (format t "C.1 AES-128 (NK=4, NR=10)~%")
;;  (format t "CIPHER (ENCRYPT):~%")
  (let ((state (make-array '(4 4))))
    (aes-encode-state state p)
;;    (format t "ROUND[~2A].INPUT    ~32,'0X~%"
;;	    0 (aes-decode-state state))
;;    (format t "ROUND[~2A].K_SCH    ~8,'0X~8,'0X~8,'0X~8,'0X~%" 0
;;	    (aref sched 0)
;;	    (aref sched 1)
;;	    (aref sched 2)
;;	    (aref sched 3))
    (aes-add-round-key state sched 0)
    (do ((round 1 (1+ round))) ((= 10 round))
;;	(format t "ROUND[~2A].START    ~32,'0x~%" round (aes-decode-state state))
	(aes-sub-bytes state)
;;	(format t "ROUND[~2A].S_BOX    ~32,'0x~%" round (aes-decode-state state))
	(aes-shift-rows state)
;;	(format t "ROUND[~2A].S_ROW    ~32,'0x~%" round (aes-decode-state state))
	(aes-mix-columns state)
;;	(format t "ROUND[~2A].M_COL    ~32,'0x~%" round (aes-decode-state state))
	(aes-add-round-key state sched round)
;;	(format t "ROUND[~2A].K_SCH    ~8,'0X~8,'0X~8,'0X~8,'0X~%" round
;;		(aref sched (+ 0 (* 4 round)))
;;		(aref sched (+ 1 (* 4 round)))
;;		(aref sched (+ 2 (* 4 round)))
;;		(aref sched (+ 3 (* 4 round))))
	)
;;    (format t "ROUND[~2A].START    ~32,'0x~%" 10 (aes-decode-state state))
    (aes-sub-bytes state)
;;    (format t "ROUND[~2A].S_BOX    ~32,'0x~%" 10 (aes-decode-state state))
    (aes-shift-rows state)
;;    (format t "ROUND[~2A].S_ROW    ~32,'0x~%" 10 (aes-decode-state state))
    (aes-add-round-key state sched 10)
;;    (format t "ROUND[~2A].K_SCH    ~8,'0X~8,'0X~8,'0X~8,'0X~%" 10
;;	    (aref sched 40)
;;	    (aref sched 41)
;;	    (aref sched 42)
;;	    (aref sched 43))
;;    (format t "ROUND[~2A].OUTPUT   ~32,'0x~%" 10 (aes-decode-state state))
    (aes-decode-state state)))


;;;
;;; aes-okayp
;;; uses the test vectors given in 
;;; Appendix C.1 of FIPS PUB 197.
;;;

(defun aes-okayp ()
  (let ((s (aes-expand-128 #x000102030405060708090A0B0C0D0E0F)))
    (= (aes-cipher-128 s #x00112233445566778899AABBCCDDEEFF)
       #x69C4E0D86A7B0430D8CDB78070B4C55A)))


