;;;; BlackLight/OpenPGP/stdio.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; Standard input/output functions
;;;;


;;;
;;; text-int (s)
;;; Given a text string s of k characters, returns an 8k-bit integer.
;;; The eight most-significant bits in the integer are
;;; the ASCII code for the first character in the string.
;;; A limitation is that strings beginning with one or more
;;; null characters (ASCII code 0x00) will not be convertible.
;;; Ex: (text-int "Pete Franusic") => 6369651700082564963458901829987
;;;

(defun text-int (s)
  (if (not (stringp s)) (error "argument not a string"))
  (let ((len (length s)) (n 0) (acc 0))
    (if (= len 0) (error "string is empty"))
    (do ((i 0 (+ i 1))) ((= i len) acc)
	(setf n (char-code (char s i)))
	(setf acc (+ (* acc 256) n)))))


;;;
;;; int-text (n)
;;; Given an 8k-bit integer, returns a text string of k characters.
;;; The eight most-significant bits in the integer are
;;; the ASCII code for the first character in the string.
;;; The integer is processed starting at least-significant n bits.
;;; Ex:  (int-text 6369651700082564963458901829987) => "Pete Franusic"
;;;

(defun int-text (n)
  (if (not (integerp n)) (error "argument not an integer"))
  (if (< n 0) (error "argument is less than 0"))
  (let ((acc n) (ch 0) (str ""))
    (do () ((= acc 0) str)
	(setf ch (rem acc 256))
	(setf str (format nil "~A~A" (code-char ch) str))
	(setf acc (/ (- acc ch) 256)))))


;;;
;;; text-int-okayp
;;;

(defun text-int-okayp ()
  (let ((x) (y) (z))
    (setf x "abcdefghijklmnopqrstuvwxyz")
    (setf y (text-int x))
    (setf z (int-text y))
    (equal x z)))


;;;
;;; hex-int (s)
;;; Given a hexadecimal string, returns an integer.
;;; Ex: (hex-int "FEDCBA9876543210") => 18364758544493064720
;;;

(defun hex-int (s)
  (if (not (stringp s)) (error "argument not a string"))
  (let ((len (length s)) (c) (n) (acc 0)
	(upper-alpha) (lower-alpha) (dec-numeric))
    (if (= len 0) (error "string is empty"))
    (do ((i 0 (+ i 1))) ((>= i len) acc)
      (setf c (char-code (char s i)))
      (setf upper-alpha (if (in-between (char-code #\A) c (char-code #\F)) T NIL))
      (setf lower-alpha (if (in-between (char-code #\a) c (char-code #\f)) T NIL))
      (setf dec-numeric (if (in-between (char-code #\0) c (char-code #\9)) T NIL))
      (if (not (or upper-alpha lower-alpha dec-numeric))
	  (error "string contains non-hexidecimal character ~A" (code-char c)))
      (if upper-alpha (setf n (- c (char-code #\A) -10)))
      (if lower-alpha (setf n (- c (char-code #\a) -10)))
      (if dec-numeric (setf n (- c (char-code #\0))))
      (setf acc (+ (* acc 16) n)))))


;;;
;;; int-hex (n)
;;; Given a decimal integer, returns a hexadecimal string.
;;; Ex: (int-hex 18364758544493064720) => "FEDCBA9876543210"
;;;

(defun int-hex (n)
  (if (not (integerp n)) (error "argument not an integer"))
  (if (< n 0) (error "argument is not a positive integer"))
  (if (= n 0) (return-from int-hex "0"))
  (let ((acc n) (digit 0) (c 0) (y ""))
    (do () ((= acc 0) y)
      (setf digit (rem acc 16))
      (setf c (if (< digit 10) 
		  (+ digit (char-code #\0))
		(+ digit -10 (char-code #\A))))
      (setf y (format nil "~A~A" (code-char c) y))
      (setf acc (/ (- acc digit) 16)))))


;;;
;;; hex-int-okayp
;;;

(defun hex-int-okayp ()
  (let ((x) (y) (z))
    (setf x (random (expt 2 1024)))
    (setf y (int-hex x))
    (setf z (hex-int y))
    (= x z)))


;;;
;;; dec-int (s)
;;; Given a decimal string, returns an integer.
;;; Ex: (dec-int "18364758544") => 18364758544
;;;

(defun dec-int (s)
  (if (not (stringp s))
      (error "s must be a string"))
  (let ((n 0))
    (dotimes (i (length s))
      (setf n (+ (* 10 n) (- (char-code (aref s i)) 48))))
    n))


;;;
;;; int-dec
;;; Given an integer, returns a decimal string.
;;; Ex: (int-dec 18364758544 => "18364758544"
;;;

(defun int-dec (n)
  (if (not (integerp n))
      (error "n must be an integer"))
  (format nil "~D" n))


;;;
;;; dec-int-okayp
;;;

(defun dec-int-okayp ()
  (let ((x) (y) (z))
    (setf x (random (expt 2 32)))
    (setf y (int-dec x))
    (setf z (dec-int y))
    (= x z)))


;;;
;;; bin-stringp
;;; takes an argument and returns true if it's a binary string.
;;;

(defun bin-stringp (s)
  (if (not (stringp s)) (return-from bin-stringp nil))
  (let ((len (length s)) (d))
    (if (= len 0) (return-from bin-stringp nil))
    (do ((i 0 (+ 1 i))) ((>= i len) t)
	(setf d (char s i))
	(if (not (or (eq #\0 d) (eq #\1 d)))
	    (return-from bin-stringp nil)))))


;;;
;;; text-bin
;;; takes an ASCII string s and returns a binary string b.
;;; The length of b will be a multiple of eight.
;;; Ex: (text-bin "abc") => "011000010110001001100011"
;;;

(defun text-bin (s)
  (if (not (stringp s)) (error "s must be an ASCII string"))
  (let ((n (length s)) (b ""))
    (dotimes (i n)
      (setf b (format nil "~A~8,'0B" b (char-code (char s i)))))
    b))


;;;
;;; bin-int (s)
;;; takes a binary string and returns a positive integer.
;;;

(defun bin-int (s)
  (if (not (bin-stringp s)) (error "argument not a binary string"))
  (let ((len (length s)) (n 0))
    (do ((i 0 (+ 1 i))) ((>= i len) n)
	(setf n (+ (* 2 n) (if (eq #\1 (char s i)) 1 0))))))


;;;
;;; int-bin (n)
;;; takes a positive integer and returns a binary string.
;;; Starts with the LSB and ends with the MSB.
;;; Uses the truncate function which returns 
;;; an integer quotient and an integer remainder.
;;; The remainder is the bit value.
;;; The quotient is the next dividend.
;;; We know we have the MSB when the quotient is 0.
;;; Uses the multiple-value-bind function to capture 
;;; the quotient and remainder values from truncate.
;;;

(defun int-bin (n)
  (if (or (not (integerp n)) (< n 0))
      (error "n must be a positive integer"))
  (let ((x) (q n) (r) (s "") (z nil))
    (do () (z s)
	(setf x (multiple-value-bind (y1 y2) (truncate q 2) (list y1 y2)))
	(setf q (car x))
	(setf r (cadr x))
	(setf s (format nil "~A~A" r s))
	(setf z (if (= q 0) t nil)))))


;;;
;;; bin-int-okayp
;;;

(defun bin-int-okayp ()
  (let ((x) (y) (z))
    (setf x (random 65536))
    (setf y (int-bin x))
    (setf z (bin-int y))
    (= x z)))


;;;
;;; split-str
;;; given a string s, returns a list z of integers.
;;;

(defun split-str (s)
  (if (not (stringp s)) (error "arg 0 must be a string."))
  (let ((n (length s)) (z nil))
    (do ((i 0 (1+ i))) ((>= i n))
	(push (char-code (char s i)) z))
    (setf z (reverse z))))


;;;
;;; unite-str
;;; given a list z of integers, returns a string s.
;;;

(defun unite-str (z)
  (if (not (listp z)) (error "arg 0 must be a list."))
  (let ((n (length z)) (x) (s ""))
    (setf s (make-string n))
    (do ((i 0 (1+ i))) ((>= i n) s)
	(setf x (code-char (pop z)))
	(setf (char s i) x))))


;;;
;;; random-string
;;; given an unsigned integer n,
;;; returns a string with n characters,
;;; where each character is a random ASCII byte.
;;;

(defun random-string (n)
  (let ((b nil))
    (dotimes (i n)
      (push (random-ascii-code) b))
    (unite-str b)))


;;;
;;; split-unite-str-okayp
;;; tests the split-str function and the unite-str function.
;;;

(defun split-unite-str-okayp ()
  (let ((xstring) (xlist) (ystring))
    (setf xstring "abcdefghijklmnopqrstuvwxyz")
    (setf xlist (split-str xstring))
    (setf ystring (unite-str xlist))
    (equal xstring ystring)))


;;;
;;; split-int
;;; given an unsigned integer n and an unsigned integer x
;;; returns a list z with n integers which are the n bytes of x.
;;;

(defun split-int (n x)
  (if (not (integerp n)) (error "arg 0 must be an integer"))
  (if (not (integerp x)) (error "arg 1 must be an integer"))
  (let ((q) (r) (z))
    (setf q x)
    (setf z nil)
    (dotimes (i n)
      (setf r (mod q 256))
      (setf q (quo q 256))
      (push r z))
    z))


;;;
;;; unite-int
;;; given a list z with n integers,
;;; returns an unsigned integer x which is the n bytes of z.
;;;

(defun unite-int (z)
  (if (not (listp z)) (error "arg 0 must be a list"))
  (let ((n) (x))
    (setf x 0)
    (setf n (length z))
    (dotimes (i n)
	(setf x (* x 256))
	(setf x (+ x (nth i z))))
    x))


;;;
;;; split-unite-int-okayp
;;; tests the split function and the unite function.
;;;

(defun split-unite-int-okayp ()
  (let ((x) (ylist) (z))
    (setf x (random (expt 2 (+ 1020 (random 5)))))
    (setf ylist (split-int (ceiling (log x 256)) x))
    (setf z (unite-int ylist))
    (= x z)))


;;;
;;; putfile
;;; given a list of 8-bit integers and the name of a binary file,
;;; writes the 8-bit integers into the file.
;;;

(defun putfile (filename z)
  (let ((opath) (ostream) (flen (length z)))
    (setf opath (make-pathname :name filename))
    (setf ostream (open opath :direction :output 
			:element-type 'unsigned-byte
			:if-exists :supersede))
    (dotimes (i flen)
	(write-byte (pop z) ostream))
    (close ostream)
    flen))


;;;
;;; getfile
;;; given the name of a binary file,
;;; reads the file and returns a list of 8-bit integers.
;;; Each byte is pushed onto the front end of the list z.
;;; After the last byte, the list z is reversed.
;;; This greatly speeds up the construction of z.
;;;

(defun getfile (filename)
  (let ((ipath) (istream) (z nil))
    (setf ipath (make-pathname :name filename))
    (setf istream (open ipath :direction :input
			:element-type 'unsigned-byte))
    (do ((n (read-byte istream nil -1)
	    (read-byte istream nil -1)))
	((minusp n))
	(push n z))
    (setf z (reverse z))
    (close istream)
    z))


;;;
;;; putfile-getfile-okayp
;;; tests the putfile function and the getfile function.
;;; Creates the 100k-byte xlist of random bytes.
;;; Write xlist to the binary file stdio.bin using putfile.
;;; Reads stdio.bin back into ylist using getfile.
;;; Deletes stdio.bin when done.
;;;

(defun putfile-getfile-okayp ()
  (let ((xlist) (ylist))
    (setf xlist nil)
    (dotimes (i 100000)
      (push (random 256) xlist))
    (setf xlist (reverse xlist))
    (putfile "../Test/stdio.bin" xlist)
    (setf ylist (getfile "../Test/stdio.bin"))
    (delete-file "../Test/stdio.bin")
    (equal xlist ylist)))


;;;
;;; getlist
;;; Given the filename of a file in CL format, returns a list.
;;;

(defun getlist (filename)
  (if (not (stringp filename)) (error "filename must be a string"))
  (read-from-string (unite-str (getfile filename))))


;;;
;;; stdio-okayp
;;;

(defun stdio-okayp ()
  (if (not (text-int-okayp)) (error "text-int-okayp failed."))
  (if (not (hex-int-okayp)) (error "hex-int-okayp failed."))
  (if (not (dec-int-okayp)) (error "dec-int-okayp failed."))
  (if (not (bin-int-okayp)) (error "bin-int-okayp failed."))
  (if (not (split-unite-str-okayp)) (error "split-unite-str-okayp failed."))
  (if (not (split-unite-int-okayp)) (error "split-unite-int-okayp failed."))
  (if (not (putfile-getfile-okayp)) (error "putfile-getfile-okayp failed."))
  T)


