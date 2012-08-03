;;;; BlackLight/OpenPGP/radix64.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; This file contains Lisp code that implements three functions:
;;;; radix64-decode takes a radix64 string and returns a list of bytes.
;;;; radix64-encode takes a list of bytes and returns a radix64 string.
;;;; radix64-okayp tests radix64-decode and radix64-encode.
;;;; 
;;;;
;;;;    The following encoding technique is taken from RFC 1521 by Borenstein
;;;;    and Freed.  It is reproduced here in a slightly edited form for convenience.
;;;;
;;;;    A 65-character subset of US-ASCII is used, enabling 6 bits to be represented 
;;;;    per printable character. (The extra 65th character, "=", is used to signify 
;;;;    a special processing function.)
;;;;
;;;;    The encoding process represents 24-bit groups of input bits as output strings 
;;;;    of 4 encoded characters. Proceeding from left to right, a 24-bit input group 
;;;;    is formed by concatenating 3 8-bit input groups.  These 24 bits are then 
;;;;    treated as 4 concatenated 6-bit groups, each of which is translated into a 
;;;;    single digit in the base64 alphabet.
;;;;
;;;;    Each 6-bit group is used as an index into an array of 64 printable characters.
;;;;    The character referenced by the index is placed in the output string.
;;;;
;;;;
;;;;                          The Base64 Alphabet
;;;;
;;;;    Dec Hex Char        Dec Hex Char        Dec Hex Char        Dec Hex Char
;;;;
;;;;      0  00    A         16  10    Q         32  20    g         48  30    w
;;;;      1  01    B         17  11    R         33  21    h         49  31    x
;;;;      2  02    C         18  12    S         34  22    i         50  32    y
;;;;      3  03    D         19  13    T         35  23    j         51  33    z
;;;;      4  04    E         20  14    U         36  24    k         52  34    0
;;;;      5  05    F         21  15    V         37  25    l         53  35    1
;;;;      6  06    G         22  16    W         38  26    m         54  36    2
;;;;      7  07    H         23  17    X         39  27    n         55  37    3
;;;;      8  08    I         24  18    Y         40  28    o         56  38    4
;;;;      9  09    J         25  19    Z         41  29    p         57  39    5
;;;;     10  0A    K         26  1A    a         42  2A    q         58  3A    6
;;;;     11  0B    L         27  1B    b         43  2B    r         59  3B    7
;;;;     12  0C    M         28  1C    c         44  2C    s         60  3C    8
;;;;     13  0D    N         29  1D    d         45  2D    t         61  3D    9
;;;;     14  0E    O         30  1E    e         46  2E    u         62  3E    +
;;;;     15  0F    P         31  1F    f         47  2F    v         63  3F    /
;;;;
;;;;                                                                  (pad)    =
;;;;
;;;;
;;;;    Special processing is performed if fewer than 24 bits are available
;;;;    at the end of the data being encoded.  A full encoding quantum is
;;;;    always completed at the end of a quantity.  When fewer than 24 input
;;;;    bits are available in an input group, zero bits are added (on the
;;;;    right) to form an integral number of 6-bit groups.  Padding at the
;;;;    end of the data is performed using the '=' character.
;;;;
;;;;    Since all base64 input is an integral number of octets, only the
;;;;    following cases can arise:
;;;;
;;;;      (1)  The final quantum of encoding input is exactly 8 bits.
;;;;           Here, the final unit of encoded output will be two
;;;;           characters followed by two "=" padding characters.
;;;; 
;;;;      (2)  The final quantum of encoding input is exactly 16 bits.
;;;;           Here, the final unit of encoded output will be three
;;;;           characters followed by one "=" padding character.
;;;; 
;;;;      (3)  The final quantum of encoding input is an integral
;;;;           multiple of 24 bits.  Here, the final unit of encoded
;;;;           output will be an integral multiple of 4 characters
;;;;           with no "=" padding.
;;;;
;;;;
;;;;    (1)   FF         11111111                     111111 110000                "/w=="
;;;;
;;;;    (2)   FF FF      11111111 11111111            111111 111111 111100         "//8="
;;;;
;;;;    (3)   FF FF FF   11111111 11111111 11111111   111111 111111 111111 111111  "////"
;;;;
;;;;


;;;
;;; radix64-char
;;; a table that includes all radix64 characters
;;;

(defconstant radix64-char (vector 
  #\A #\B #\C #\D #\E #\F #\G #\H #\I #\J #\K #\L #\M #\N #\O #\P 
  #\Q #\R #\S #\T #\U #\V #\W #\X #\Y #\Z #\a #\b #\c #\d #\e #\f
  #\g #\h #\i #\j #\k #\l #\m #\n #\o #\p #\q #\r #\s #\t #\u #\v 
  #\w #\x #\y #\z #\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9 #\+ #\/
  #\= ))


;;;
;;; radix64p
;;; returns T iff argument is a radix64 character (#\A #\B ...).
;;; returns NIL if argument is the radix64 pad (#\=).
;;;

(defun radix64p (c)
  (do ((i 0 (1+ i))) ((> i 63) -1)
      (if (eq c (svref radix64-char i))
	  (return-from radix64p T)))
  NIL)


;;;
;;; radix64-code (c)
;;; takes a radix64 character c and
;;; returns the corresponding radix64 code, or
;;; returns -1 if the character does not exist.
;;;

(defun radix64-code (c)
  (if (not (characterp c)) (error "c is not a character"))
  (do ((i 0 (1+ i))) ((> i 64) -1)
      (if (eq c (svref radix64-char i))
	  (return-from radix64-code i))))


;;;
;;; radix64-one-byte
;;; takes a list b of one integer in [0,255]
;;; and returns a list of two radix64 chars and two pads.
;;;

(defun radix64-one-byte (b)
  (if (not (listp b)) (error "b is not a list"))
  (if (/= 1 (length b)) (error "b is not one byte in length"))
  (let ((n (unite-int b)))
    (list (svref radix64-char (quo n 4))
	  (svref radix64-char (* 16 (rem n 4)))
	  #\=
	  #\=)))


;;;
;;; radix64-two-bytes
;;; takes a list of two integers in [0,255]
;;; and returns a list of three radix64 chars and one pad.
;;;

(defun radix64-two-bytes (b)
  (if (not (listp b)) (error "b is not a list"))
  (if (/= 2 (length b)) (error "b is not two bytes in length"))
  (let ((n (unite-int b)))
    (list (svref radix64-char (quo n 1024))
	  (svref radix64-char (quo (rem n 1024) 16))
	  (svref radix64-char (* 4 (rem n 16)))
	  #\=)))


;;;
;;; radix64-three-bytes
;;; takes a list b of three integers in [0,255]
;;; and returns a list of four radix64 chars and no pads.
;;;

(defun radix64-three-bytes (b)
  (if (not (listp b)) (error "b is not a list"))
  (if (/= 3 (length b)) (error "b is not three bytes in length"))
  (let ((n (unite-int b)))
    (list (svref radix64-char (quo n 262144))
	  (svref radix64-char (quo (rem n 262144) 4096))
	  (svref radix64-char (quo (rem n 4096) 64))
	  (svref radix64-char (rem n 64)))))


;;;
;;; radix64-two-chars
;;; takes a list of two radix64 chars and two pads
;;; and returns a list of one integer in [0,255].
;;;

(defun radix64-two-chars (r)
  (if (not (listp r)) (error "r is not a list"))
  (if (/= 4 (length r)) (error "r is not 4 elements"))
  (if (not (radix64p (nth 0 r))) (error "r[0] is not a radix64 char"))
  (if (not (radix64p (nth 1 r))) (error "r[1] is not a radix64 char"))
  (if (not (eq (nth 2 r) #\=)) (error "r[2] is not a radix64 pad"))
  (if (not (eq (nth 3 r) #\=)) (error "r[3] is not a radix64 pad"))
  (split-int 1 (+ (* (radix64-code (nth 0 r)) 4)
		  (/ (logand #x30 (radix64-code (nth 1 r))) 16))))


;;;
;;; radix64-three-chars
;;; takes a list of three radix64 characters and one radix64 pad
;;; and returns a list of two integers in [0,255].
;;;

(defun radix64-three-chars (r)
  (if (not (listp r)) (error "r is not a list"))
  (if (/= 4 (length r)) (error "r is not 4 elements"))
  (if (not (radix64p (nth 0 r))) (error "r[0] is not a radix64 char"))
  (if (not (radix64p (nth 1 r))) (error "r[1] is not a radix64 char"))
  (if (not (radix64p (nth 2 r))) (error "r[2] is not a radix64 char"))
  (if (not (eq (nth 3 r) #\=)) (error "r[3] is not a radix64 pad"))
  (split-int 2 (+ (* (radix64-code (nth 0 r)) 1024)
		  (* (radix64-code (nth 1 r)) 16)
		  (/ (logand #x3C (radix64-code (nth 2 r))) 4))))


;;;
;;; radix64-four-chars
;;; takes a list of three radix64 characters and one radix64 pad
;;; and returns a list of three integers in [0,255].
;;;

(defun radix64-four-chars (r)
  (if (not (listp r)) (error "r is not a list"))
  (if (/= 4 (length r)) (error "r is not 4 elements"))
  (if (not (radix64p (nth 0 r))) (error "r[0] is not a radix64 char"))
  (if (not (radix64p (nth 1 r))) (error "r[1] is not a radix64 char"))
  (if (not (radix64p (nth 2 r))) (error "r[2] is not a radix64 char"))
  (if (not (radix64p (nth 3 r))) (error "r[3] is not a radix64 char"))
  (split-int 3 (+ (* (radix64-code (nth 0 r)) 262144)
		  (* (radix64-code (nth 1 r)) 4096)
		  (* (radix64-code (nth 2 r)) 64)
		  (radix64-code (nth 3 r)))))


;;;
;;; radix64-encode
;;; takes a list of bytes b and returns a radix64 string.
;;; Repeatedly pops three bytes off list b and processes them with radix64-three-bytes.
;;; When there is only one or two bytes left, process them with either
;;; radix64-one-byte or radix64-two-bytes and exits normally.
;;;

(defun radix64-encode (b)
  (if (not (listp b)) (error "b is not a list"))
  (if (= 0 (length b)) (error "b is an empty list"))
  (let ((r) (s nil))
    (while (>= (length b) 3)
      (setf r (radix64-three-bytes (list (pop b) (pop b) (pop b))))
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s))
    (while (>= (length b) 2)
      (setf r (radix64-two-bytes (list (pop b) (pop b))))
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s))
    (while (>= (length b) 1)
      (setf r (radix64-one-byte (list (pop b))))
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s)
      (push (char-code (pop r)) s))
    (unite-str (reverse s))))

;;;
;;; radix64-decode
;;; takes a radix64 string s and returns a list of bytes.
;;; The length of s must be a multiple of 4.
;;;

(defun radix64-decode (s)
  (if (not (stringp s)) (error "s is not a string"))
  (if (= (length s) 0) (error "s is an empty string"))
  (if (/= 0 (rem (length s) 4)) (error "length s must be multple of 4"))
  (let ((n) (r) (q) (p) (b nil))
    (setf r (mapcar #'code-char (split-str s)))
    (setf n (quo (length r) 4))
    (dotimes (i n)
      (setf q (list (pop r) (pop r) (pop r) (pop r)))
      (when (and (eq #\= (nth 2 q))
		 (eq #\= (nth 3 q)))
	(setf p (radix64-two-chars q))
	(push (pop p) b))
      (when (and (not (eq #\= (nth 2 q)))
		 (eq #\= (nth 3 q)))
	(setf p (radix64-three-chars q))
	(push (pop p) b)
	(push (pop p) b))
      (when (and (not (eq #\= (nth 2 q)))
		 (not (eq #\= (nth 3 q))))
	(setf p (radix64-four-chars q))
	(push (pop p) b)
	(push (pop p) b)
	(push (pop p) b)))
    (reverse b)))


;;;
;;; radix64-okayp
;;; tests radix64-encode and radix64-decode.
;;;

(defun radix64-okayp ()
  (let ((x) (y) (z))
    (dotimes (i 10)
      (setf x (random-bytes 1))
      (setf y (radix64-one-byte x))
      (setf z (radix64-two-chars y))
      (if (not (equal x z)) (return-from radix64-okayp NIL)))
    (dotimes (i 10)
      (setf x (random-bytes 2))
      (setf y (radix64-two-bytes x))
      (setf z (radix64-three-chars y))
      (if (not (equal x z)) (return-from radix64-okayp NIL)))
    (dotimes (i 10)
      (setf x (random-bytes 3))
      (setf y (radix64-three-bytes x))
      (setf z (radix64-four-chars y))
      (if (not (equal x z)) (return-from radix64-okayp NIL)))
    (dotimes (i 5)
      (setf x (radix64-encode (random-bytes 90)))
      (setf y (radix64-decode x))
      (setf z (radix64-encode y))
      (if (not (equal x z)) (return-from radix64-okayp NIL)))
    (dotimes (i 5)
      (setf x (radix64-encode (random-bytes 91)))
      (setf y (radix64-decode x))
      (setf z (radix64-encode y))
      (if (not (equal x z)) (return-from radix64-okayp NIL)))
    (dotimes (i 5)
      (setf x (radix64-encode (random-bytes 92)))
      (setf y (radix64-decode x))
      (setf z (radix64-encode y))
      (if (not (equal x z)) (return-from radix64-okayp NIL)))
    T))


