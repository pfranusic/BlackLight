;;;; BlackLight/OpenPGP/time.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; BlackLight OpenPGP time functions
;;;; OpenPGP specifies several date and time values.
;;;; E.g., the SIGNATURE-CREATION-TIME subpacket contains four bytes
;;;; that represent the precise date and time that a signature was created.
;;;; It is the number of seconds elapsed since Epoch 1970.
;;;; [See RFC-4880 section 3.5].
;;;;
;;;; quasi ISO-8601 date-time format
;;;; "YYYY-mmm-DD HH:MM:SS UTC"
;;;; "YYYY" is four decimal digits, zero padded, in [0000,9999].
;;;; "mmm" is three alpha characters, in ("Jan" "Feb" ... "Dec").
;;;; "DD" is two decimal digits, zero padded, in [00,31].
;;;; "HH" is two decimal digits, zero padded, in [00,23].
;;;; "MM" is two decimal digits, zero padded, in [00,59].
;;;; "SS" is two decimal digits, zero padded, in [00,59].
;;;; "UTC" is a literal string.
;;;; "-" and " " and ":" are literal characters.
;;;; Example: "2011-May-21 18:00:00 UTC"
;;;;
;;;; time functions:
;;;; epoch1970-secs returns the number of seconds elapsed since Epoch 1970.
;;;; decode-epoch1970-secs takes an integer and returns a ISO formatted time string.
;;;; encode-epoch1970-secs takes a ISO formatted time string and returns an integer.
;;;;
;;;; OpenMCL library functions:
;;;; get-universal-time returns the number of seconds elapsed since Epoch 1900.
;;;; decode-universal-time takes an integer and returns multiple values.
;;;; encode-universal-time takes multiple values and returns an integer.
;;;;
;;;; Here's some examples on a Mac 0S X with time-zone set to 0 (GMT).
;;;; decode-universal-time returns sec, min, hour, day-of-month, month, year, 
;;;; day-of-week (?), daylight-p, and zone.
;;;; encode-universal-time accepts sec, min, hour, day-of-month, month, year.
;;;;
;;;; ? (get-universal-time)
;;;; 3515003643
;;;; ? (decode-universal-time )
;;;; 3
;;;; 54
;;;; 21
;;;; 21
;;;; 5
;;;; 2011
;;;; 5
;;;; NIL
;;;; 0
;;;; ? (encode-universal-time 3 54 21 21 5 2011)
;;;; 3515003643
;;;;
;;;; Now we need to get the difference in seconds between Epoch 1970 and Epoch 1900.
;;;; We'll add and subtract this number from Epoch 1900 seconds (get-universal-time)
;;;; so that we can use decode-universal-time to implememt decode-epoch1970-secs
;;;; and encode-universal-time to implememt encode-epoch1970-secs.
;;;; That way we can avoid calculating leap years and all that nasty stuff.
;;;; First we encode "1900-jan-01 00:00:00 UTC" and make sure it's 0.
;;;; Next we encode "1970-jan-01 00:00:00 UTC".  That's our difference value.
;;;;
;;;; ? (encode-universal-time 0 0 0 1 1 1900)
;;;; 0
;;;; ? (encode-universal-time 0 0 0 1 1 1970)
;;;; 2208988800
;;;;


;;;
;;; epoch1970-secs
;;; returns the number of seconds elapsed since Epoch 1970.
;;; [See RFC-4880 section 3.5].
;;;

(defun epoch1970-secs ()
  (- (get-universal-time) 2208988800))


;;;
;;; month-name
;;; list with twelve three-letter strings, abbreviated names for the months.
;;;

(defconstant month-name
  '("Jan" "Feb" "Mar" "Apr" "May" "Jun" "Jul" "Aug" "Sep" "Oct" "Nov" "Dec"))


;;;
;;; month-number
;;; given a three-char month string, returns the month number.
;;;

(defun month-number (s)
  (if (not (stringp s))
      (error "s must be a string"))
  (if (/= 3 (length s))
      (error "s must be exactly three characters"))
  (dotimes (i 12)
    (if (equal s (nth i month-name))
	(return-from month-number (1+ i))))
  (error "s is invalid"))


;;;
;;; decode-epoch1970-secs
;;; takes an integer and returns a formatted time string.
;;;

(defun decode-epoch1970-secs (n)
  (if (not (integerp n)) (error "n must be an integer"))
  (if (< n 0) (error "n must be greater or equal to 0"))
  (let ((time-list (multiple-value-bind (r0 r1 r2 r3 r4 r5) 
					(decode-universal-time (+ n 2208988800))
					(list r5 r4 r3 r2 r1 r0))))
    (format nil "~D-~A-~2,'0,,D ~2,'0,,D:~2,'0,,D:~2,'0,,D UTC"
	    (nth 0 time-list)
	    (nth (1- (nth 1 time-list)) month-name)
	    (nth 2 time-list)
	    (nth 3 time-list)
	    (nth 4 time-list)
	    (nth 5 time-list))))


;;;
;;; encode-epoch1970-secs
;;; takes a formatted time string and returns an integer.
;;; Example: "2011-May-21 17:59:43 UTC"
;;; index:    012345678901234567890123
;;;

(defun encode-epoch1970-secs (s)
  (if (not (and (stringp s)
		(= 24 (length s))
		(decimal-digit-p (aref s 0))
		(decimal-digit-p (aref s 1))
		(decimal-digit-p (aref s 2))
		(decimal-digit-p (aref s 3))
		(eq #\- (aref s 4))
		(upper-alpha-p (aref s 5))
		(lower-alpha-p (aref s 6))
		(lower-alpha-p (aref s 7))
		(eq #\- (aref s 8))
		(decimal-digit-p (aref s 9))
		(decimal-digit-p (aref s 10))
		(eq #\Space (aref s 11))
		(decimal-digit-p (aref s 12))
		(decimal-digit-p (aref s 13))
		(eq #\: (aref s 14))
		(decimal-digit-p (aref s 15))
		(decimal-digit-p (aref s 16))
		(eq #\: (aref s 17))
		(decimal-digit-p (aref s 18))
		(decimal-digit-p (aref s 19))
		(eq #\Space (aref s 20))
		(eq #\U (aref s 21))
		(eq #\T (aref s 22))
		(eq #\C (aref s 23))))
      (error "s must have form \"YYYY-mmm-DD HH:MM:SS UTC\""))

  (let ((r5 (dec-int (subseq s 0 4)))
	(r4 (month-number (subseq s 5 8)))
	(r3 (dec-int (subseq s 9 11)))
	(r2 (dec-int (subseq s 12 14)))
	(r1 (dec-int (subseq s 15 17)))
	(r0 (dec-int (subseq s 18 20))))
    (if (not (and (<= 1 r3) (<= r3 31))) (error "DD must be in [1,31]"))
    (if (not (and (<= 0 r2) (<= r2 23))) (error "HH must be in [0,23]"))
    (if (not (and (<= 0 r1) (<= r1 59))) (error "MM must be in [0,59]"))
    (if (not (and (<= 0 r0) (<= r0 59))) (error "SS must be in [0,59]"))
    (- (encode-universal-time r0 r1 r2 r3 r4 r5) 2208988800)))


;;;
;;; epoch1970-timestamp
;;; prints the current date and time in quasi ISO-8601 format.
;;;

(defun epoch1970-timestamp ()
  (decode-epoch1970-secs (epoch1970-secs)))


;;;
;;; date
;;; prints the current date and time in quasi ISO-8601 format.
;;;

(defun date ()
  (decode-epoch1970-secs (epoch1970-secs)))


;;;
;;; time-stringp
;;; returns T iff s is a valid time string.
;;;

(defun time-stringp (s)
   (and (stringp s)
	(= 24 (length s))
	(decimal-digit-p (aref s 0))
	(decimal-digit-p (aref s 1))
	(decimal-digit-p (aref s 2))
	(decimal-digit-p (aref s 3))
	(in-between 1969 (dec-int (subseq s 0 4)) 2107)
	(eq #\- (aref s 4))
	(memberp month-name (subseq s 5 8))
	(eq #\- (aref s 8))
	(decimal-digit-p (aref s 9))
	(decimal-digit-p (aref s 10))
	(in-between 1 (dec-int (subseq s 9 11)) 31)
	(eq #\Space (aref s 11))
	(decimal-digit-p (aref s 12))
	(decimal-digit-p (aref s 13))
	(in-between 0 (dec-int (subseq s 12 14)) 23)
	(eq #\: (aref s 14))
	(decimal-digit-p (aref s 15))
	(decimal-digit-p (aref s 16))
	(in-between 0 (dec-int (subseq s 15 17)) 59)
	(eq #\: (aref s 17))
	(decimal-digit-p (aref s 18))
	(decimal-digit-p (aref s 19))
	(in-between 0 (dec-int (subseq s 18 20)) 59)
	(eq #\Space (aref s 20))
	(equal "UTC" (subseq s 21 24))))
  

;;;
;;; time-okayp
;;;

(defun time-okayp ()
  (let ((x) (y) (z))
    (setf x (epoch1970-secs))
    (setf y (decode-epoch1970-secs x))
    (setf z (encode-epoch1970-secs y))
    (= x z)))


