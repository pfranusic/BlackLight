;;;; BlackLight/OpenPGP/subpacket.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; implements OpenPGP V4 signature subpackets
;;;;
;;;;
;;;; DEVELOPMENT NOTES:
;;;;
;;;; RFC-4880 section 5.2.3 specifies OpenPGP V4 signature packet format.
;;;; This format includes two subpacket data sets (blocks).
;;;; The C2 module parses and builds signature packets.
;;;; This module, subpacket, parses and builds subpacket blocks.
;;;; There are three main functions in this module:
;;;; *  parse-subpacket-block takes a byte list and returns a field list.
;;;; *  build-subpacket-block takes a field list and returns a byte list.
;;;; *  subpacket-okayp tests build-subpacket-block and parse-subpacket-block.
;;;;
;;;; parse-subpacket-block
;;;; This function is normally called by parse-packet-C2-body.
;;;; parse-subpacket-block takes a byte list and returns a field list.
;;;; The input is a list of bytes, a subpacket block.
;;;; The output is a list of lists, where each inner list contains
;;;; a subpacket-length symbol, a subpacket-length integer, a subpacket-type symbol,
;;;; and any additional fields as required by RFC-4880.
;;;; 
;;;; build-subpacket-block
;;;; This function is normally called by build-packet-C2-body.
;;;; build-subpacket-block takes a field list and returns a byte list.
;;;; The input is a list of lists, where each inner list contains
;;;; a subpacket-length symbol, a subpacket-length integer, a subpacket-type symbol,
;;;; and any additional fields as required by RFC-4880.
;;;; The output is a list of bytes, a subpacket block.
;;;; 
;;;; subpacket-okayp
;;;; This function is normally called by system-test.
;;;; It tests build-subpacket-block and parse-subpacket-block.
;;;; The input is a list of lists.  The output is also a list of lists.
;;;; The input list is compared with the output list.
;;;; If they are identical, subpacket-okayp returns T.
;;;; 
;;;; First we'll get parse-subpacket-block to take one of these and return 
;;;; a list of lists, where each inner list includes only a subpacket-length symbol, 
;;;; a subpacket-length integer, a subpacket-type symbol, and a list of bytes.
;;;; Later we'll pass each of these inner lists to the appropriate subpacket function 
;;;; to parse the list of bytes.
;;;; We'll use three functions to do this:
;;;; *  subpacket-length-symbol returns one of three length symbols.
;;;; *  subpacket-length-integer returns the length of the first subpacket.
;;;; *  subpacket-type-name returns one of twenty-three subpacket names.
;;;;
;;;; parse-subpacket-block shall parse the subpacket bodies.
;;;; Let there be a function for each packet type.  (There are 27 of them).
;;;; Let each of these be called by the parse-subpacket-body function.
;;;; Let the name of each function be in the form parse-subpacket-DD-body,
;;;; where DD is a two-digit decimal value that corresponds to the integers
;;;; in the type column of the subpacket-info table.
;;;;


;;;
;;; subpacket-info
;;; See RFC-4880 section 5.2.3.1
;;;

(defconstant subpacket-info
;;   type                            name                    pfunc                    bfunc
  '((0                         RESERVED-0           parse-reserved           build-reserved)
    (1                         RESERVED-1           parse-reserved           build-reserved)
    (2            SIGNATURE-CREATION-TIME  parse-subpacket-02-body  build-subpacket-02-body)
    (3          SIGNATURE-EXPIRATION-TIME  parse-subpacket-03-body  build-subpacket-03-body)
    (4           EXPORTABLE-CERTIFICATION  parse-subpacket-04-body  build-subpacket-04-body)
    (5                    TRUST-SIGNATURE  parse-subpacket-05-body  build-subpacket-05-body)
    (6                 REGULAR-EXPRESSION  parse-subpacket-06-body  build-subpacket-06-body)
    (7                          REVOCABLE  parse-subpacket-07-body  build-subpacket-07-body)
    (8                         RESERVED-8           parse-reserved           build-reserved)
    (9                KEY-EXPIRATION-TIME  parse-subpacket-09-body  build-subpacket-09-body)
    (10                       RESERVED-10           parse-reserved           build-reserved)
    (11    PREFERRED-SYMMETRIC-ALGORITHMS  parse-subpacket-11-body  build-subpacket-11-body)
    (12                    REVOCATION-KEY  parse-subpacket-12-body  build-subpacket-12-body)
    (13                       RESERVED-13           parse-reserved           build-reserved)
    (14                       RESERVED-14           parse-reserved           build-reserved)
    (15                       RESERVED-15           parse-reserved           build-reserved)
    (16                            ISSUER  parse-subpacket-16-body  build-subpacket-16-body)
    (17                       RESERVED-17           parse-reserved           build-reserved)
    (18                       RESERVED-18           parse-reserved           build-reserved)
    (19                       RESERVED-19           parse-reserved           build-reserved)
    (20                     NOTATION-DATA  parse-subpacket-20-body  build-subpacket-20-body)
    (21         PREFERRED-HASH-ALGORITHMS  parse-subpacket-21-body  build-subpacket-21-body)
    (22  PREFERRED-COMPRESSION-ALGORITHMS  parse-subpacket-22-body  build-subpacket-22-body)
    (23            KEY-SERVER-PREFERENCES  parse-subpacket-23-body  build-subpacket-23-body)
    (24              PREFERRED-KEY-SERVER  parse-subpacket-24-body  build-subpacket-24-body)
    (25                   PRIMARY-USER-ID  parse-subpacket-25-body  build-subpacket-25-body)
    (26                        POLICY-URI  parse-subpacket-26-body  build-subpacket-26-body)
    (27                         KEY-FLAGS  parse-subpacket-27-body  build-subpacket-27-body)
    (28                   SIGNERS-USER-ID  parse-subpacket-28-body  build-subpacket-28-body)
    (29             REASON-FOR-REVOCATION  parse-subpacket-29-body  build-subpacket-29-body)
    (30                          FEATURES  parse-subpacket-30-body  build-subpacket-30-body)
    (31                  SIGNATURE-TARGET  parse-subpacket-31-body  build-subpacket-31-body)
    (32                EMBEDDED-SIGNATURE  parse-subpacket-32-body  build-subpacket-32-body)
    (100                 EXPERIMENTAL-100           parse-reserved           build-reserved)
    (101                 EXPERIMENTAL-101           parse-reserved           build-reserved)
    (102                 EXPERIMENTAL-102           parse-reserved           build-reserved)
    (103                 EXPERIMENTAL-103           parse-reserved           build-reserved)
    (104                 EXPERIMENTAL-104           parse-reserved           build-reserved)
    (105                 EXPERIMENTAL-105           parse-reserved           build-reserved)
    (106                 EXPERIMENTAL-106           parse-reserved           build-reserved)
    (107                 EXPERIMENTAL-107           parse-reserved           build-reserved)
    (108                 EXPERIMENTAL-108           parse-reserved           build-reserved)
    (109                 EXPERIMENTAL-109           parse-reserved           build-reserved)
    (110                 EXPERIMENTAL-110           parse-reserved           build-reserved)))


;;;
;;; subpacket-type-index
;;; Input is a type integer n, usually from message byte list.
;;; Output is an index integer, the list in subpacket-info that type n appears.
;;; ? (subpacket-type-index 100)
;;; 33
;;;

(defun subpacket-type-index (n)
  (if (not (integerp n)) (error "n must be an integer"))
  (dotimes (i (length subpacket-info))
    (if (= n (nth 0 (nth i subpacket-info)))
	(return-from subpacket-type-index i)))
  (error "~A is not in subpacket-info" n))


;;;
;;; subpacket-name-index
;;; Input is a name symbol s, usually from message field list.
;;; Output is an index integer, the list in subpacket-info that symbol s appears.
;;; ? (subpacket-name-index 'EXPERIMENTAL-100)
;;; 33
;;;

(defun subpacket-name-index (s)
  (if (not (symbolp s)) (error "s must be a symbol"))
  (dotimes (i (length subpacket-info))
    (if (eq s (nth 1 (nth i subpacket-info)))
	(return-from subpacket-name-index i)))
  (error "~A is not in subpacket-info" s))


;;;
;;; subpacket-length-symbol
;;; The input is a list of bytes (a subpacket block).
;;; The output is a symbol that specifies the number of bytes in the length field
;;; for the first subpacket of the block.
;;; The value of the first byte in the input determines this symbol.
;;; If it's in [0,191] then SUBPACKET-A.
;;; ? (subpacket-length-symbol '(5 101 102 103 104 105))
;;; SUBPACKET-A
;;; If it's in [192,254] then SUBPACKET-B.
;;; ? (subpacket-length-symbol '(192 5 101 102 103 104 105))
;;; SUBPACKET-B
;;; If it's 255, then SUBPACKET-C.
;;; ? (subpacket-length-symbol '(255 0 0 0 5 101 102 103 104 105))
;;; SUBPACKET-C
;;; We use a sieve approach, hence the "return-from" operator.
;;;

(defun subpacket-length-symbol (b)
  (if (not (blistp b)) (error "b must be a non-empty list of bytes"))
  (if (< (nth 0 b) 192) (return-from subpacket-length-symbol 'SUBPACKET-A))
  (if (< (nth 0 b) 255) (return-from subpacket-length-symbol 'SUBPACKET-B))
  'SUBPACKET-C)


;;;
;;; subpacket-type-name
;;; Input is a subpacket length symbol and a list of bytes (a subpacket block).
;;; Output is a subpacket name from the subpacket-info table.
;;; ? (subpacket-type-name 'SUBPACKET-A '(2 30 5))
;;; FEATURES
;;;

(defun subpacket-type-name (s b)
  (if (not (symbolp s)) (error "s must be a symbol"))
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (case s
	(SUBPACKET-A  (nth 1 (nth (subpacket-type-index (nth 1 b)) subpacket-info)))
	(SUBPACKET-B  (nth 1 (nth (subpacket-type-index (nth 2 b)) subpacket-info)))
	(SUBPACKET-C  (nth 1 (nth (subpacket-type-index (nth 5 b)) subpacket-info)))
	(otherwise    (error "symbol s is invalid"))))


;;;
;;; subpacket-length-integer
;;; The input is a subpacket length symbol and a list of bytes (a subpacket block).
;;; The output is an integer, the number of bytes in the body for the first subpacket in the block.
;;; The value of the length symbol determines the length computation.
;;; If it's SUBPACKET-A then simply return (nth 0 b).
;;; ? (subpacket-length-integer 'SUBPACKET-A '(63))
;;; 63
;;; If it's SUBPACKET-B then return an integer that combines (nth 0 b) and (nth 1 b).
;;; ? (subpacket-length-integer 'SUBPACKET-B '(194 1))
;;; 705
;;; If it's SUBPACKET-C then return an integer that combines (nth 1 b) thru (nth 4 b).
;;; ? (subpacket-length-integer 'SUBPACKET-C '(255 7 91 205 21))
;;; 123456789
;;;

(defun subpacket-length-integer (s b)
  (if (not (symbolp s)) (error "s must be a symbol"))
  (if (not (blistp b)) (error "b must be a non-empty list of bytes"))
  (case s
	(SUBPACKET-A  (nth 0 b))
	(SUBPACKET-B  (+ (* 256 (nth 0 b))
			 (nth 1 b)
			 -48960))
	(SUBPACKET-C  (+ (* (nth 1 b) 16777216)
			 (* (nth 2 b) 65536)
			 (* (nth 3 b) 256)
			 (nth 4 b)))
	(otherwise    (error "symbol s is invalid"))))


;;;
;;; subpacket-length-bytes
;;; Input is a subpacket length symbol and a length integer.
;;; Output is a list of bytes that specifies the length.
;;; ? (subpacket-length-bytes 'SUBPACKET-A 63)
;;; (63)
;;; ? (subpacket-length-bytes 'SUBPACKET-B 705)
;;; (194 1)
;;; ? (subpacket-length-bytes 'SUBPACKET-C 123456789)
;;; (255 7 91 205 21)
;;;

(defun subpacket-length-bytes (s n)
  (if (not (symbolp s)) (error "s must be a symbol"))
  (if (not (integerp n)) (error "n must be an integer"))
  (case s
	(SUBPACKET-A  (list n))
	(SUBPACKET-B  (split-int 2 (+ 48960 n)))
	(SUBPACKET-C  (append '(255) (split-int 4 n)))
	(otherwise    (error "symbol s is invalid"))))


;;;
;;; parse-subpacket-body
;;; Called by parse-subpacket.
;;; Input is a subpacket name symbol s and a list of bytes b.
;;; Output is an expression that represents the contents of the packet body.
;;; We use the eval operator to execute functions from the subpacket-info table.
;;; ? (parse-subpacket-body 'SIGNATURE-CREATION-TIME '(77 163 36 164))
;;; ("2011-Apr-11 15:56:20 UTC")
;;;

(defun parse-subpacket-body (s b)
  (if (not (symbolp s)) (error "s must be a symbol"))
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (let ((func-name (gensym)) (body-list (gensym)))
    (setf func-name (nth 2 (nth (subpacket-name-index s) subpacket-info)))
    (setf body-list (copy-list b))
    (eval `(,func-name '(,@body-list)))))


;;;
;;; parse-subpacket
;;; Called by parse-subpacket-block.
;;; Input is a list of bytes.
;;; Output is a list of fields that represent one subpacket.
;;; ? (parse-subpacket '(5 2 77 163 36 164))
;;; (SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC")
;;;

(defun parse-subpacket (b)
  (if (not (blistp b)) (error "b must be a non-empty list of bytes"))
  (let ((sub-header) (sub-length) (sub-name) (sub-first) (sub-lastz) (sub-body))
    (setf sub-header (subpacket-length-symbol b))
    (setf sub-length (subpacket-length-integer sub-header b))
    (setf sub-name (subpacket-type-name sub-header b))
    (setf sub-first (case sub-header
		     (SUBPACKET-A 2)
		     (SUBPACKET-B 3)
		     (SUBPACKET-C 6)))
    (setf sub-lastz (case sub-header
		     (SUBPACKET-A (+ 1 sub-length))
		     (SUBPACKET-B (+ 2 sub-length))
		     (SUBPACKET-C (+ 5 sub-length))))
    (setf sub-body (parse-subpacket-body
		    sub-name (subseq b sub-first sub-lastz)))
    (append (list sub-header sub-name) sub-body)))


;;;
;;; pop-subpacket
;;; Called by parse-subpacket-block.
;;; Input s a symbol: SUBPACKET-A, SUBPACKET-A, or SUBPACKET-C.
;;; Input n is an integer, the length of a first subpacket body.
;;; Input b is a list of m1 + m2 bytes, where m1 is the length of the
;;; first subpacket, and m1 is the length of the second subpacket.
;;; Output is a list of m2 bytes.
;;; ? (pop-subpacket '(5 2 77 163 36 164 2 27 47))
;;; (2 27 47)
;;;

(defun pop-subpacket (b)
  (if (not (blistp b)) (error "b must be a list of bytes"))
  (let ((s) (n))
    (setf s (subpacket-length-symbol b))
    (setf n (subpacket-length-integer s b))
    (case s
	  (SUBPACKET-A (dotimes (i (+ 1 n)) (pop b)))
	  (SUBPACKET-B (dotimes (i (+ 2 n)) (pop b)))
	  (SUBPACKET-C (dotimes (i (+ 5 n)) (pop b))))
    b))


;;;
;;; parse-subpacket-block
;;; Input is a list of bytes, a block of subpackets.
;;; Output is a list of parsed subpackets.
;;; ? (parse-subpacket-block '(5 2 77 163 36 164 2 27 47))
;;; ((SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC")
;;;  (SUBPACKET-A KEY-FLAGS "101111"))
;;;

(defun parse-subpacket-block (x)
  (if (not (blistp x)) (error "x must be a list of bytes"))
  (let ((y) (z nil))
    (while (/= 0 (length x))
      (setf y (parse-subpacket x))
      (setf z (append z (list y)))
      (setf x (pop-subpacket x)))
    z))


;;;
;;; build-subpacket
;;; Input is a parsed subpacket list.
;;; Output is a list of bytes.
;;; ? (build-subpacket '(SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC"))
;;; (5 2 77 163 36 164)
;;;

(defun build-subpacket (x)
  (if (not (listp x)) (error "x must be a list"))
  (let ((sub-line) (func-name (gensym)) (body-list (gensym))
	(sub-body) (sub-type) (sub-length))
    (setf sub-line (nth (subpacket-name-index (nth 1 x)) subpacket-info))
    (setf func-name (nth 3 sub-line))
    (setf body-list (subseq x 2 (length x)))
    (setf sub-body (eval `(,func-name '(,@body-list))))
    (setf sub-type (list (nth 0 sub-line)))
    (setf sub-length (subpacket-length-bytes (nth 0 x) (1+ (length sub-body))))
    (append sub-length sub-type sub-body)))


;;;
;;; build-subpacket-block
;;; Input is a list of parsed subpackets.
;;; Output is a list of bytes.
;;; ? (build-subpacket-block '((SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC") (SUBPACKET-A KEY-FLAGS "101111")))
;;; (5 2 77 163 36 164 2 27 47)
;;;

(defun build-subpacket-block (x)
  (if (not (listp x)) (error "x must be a list"))
  (let ((y) (z nil))
    (dotimes (i (length x))
      (setf y (build-subpacket (nth i x)))
      (setf z (append z y)))
    z))


;;;
;;; sample-subpacket-blocks
;;; These are used to test this module.
;;;

(defconstant sample-subpacket-blocks
  '(
    ((SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC")
     (SUBPACKET-A KEY-FLAGS "101111")
     (SUBPACKET-A PREFERRED-SYMMETRIC-ALGORITHMS AES-256 AES-192 AES-128 CAST5 TRIPLE-DES)
     (SUBPACKET-A PREFERRED-HASH-ALGORITHMS SHA-1 SHA-256 RIPEMD-160)
     (SUBPACKET-A PREFERRED-COMPRESSION-ALGORITHMS ZLIB BZIP2 ZIP)
     (SUBPACKET-A FEATURES "1")
     (SUBPACKET-A KEY-SERVER-PREFERENCES "10000000"))

    ((SUBPACKET-A ISSUER "F894450D1BBE6287"))

    ((SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC")
     (SUBPACKET-A KEY-FLAGS "101110"))

    ))


;;;
;;; subpacket-okayp
;;; tests build-subpacket-block and parse-subpacket-block.
;;;

(defun subpacket-okayp ()
  (let ((x) (y) (z))
    (dotimes (i (length sample-subpacket-blocks))
      (setf x (nth i sample-subpacket-blocks))
      (setf y (build-subpacket-block x))
      (setf z (parse-subpacket-block y))
      (if (not (equal x z))
	  (return-from subpacket-okayp NIL))))
  T)


