;;;; BlackLight/OpenPGP/packet.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; build-packet and parse-packet functions
;;;; 


;;;
;;; build-packet-body
;;; takes a packet-type s and a field list f and returns a byte list.
;;;

(defun build-packet-body (s f)
  (case s
	(PARTIAL-PACKET                              (nth 0 f))
	(PKE-SESSION-KEY-PACKET                      (build-packet-C1-body f))
	(SIGNATURE-PACKET                            (build-packet-C2-body f))
	(ONE-PASS-SIGNATURE-PACKET                   (build-packet-C4-body f))
	(PUBLIC-KEY-PACKET                           (build-packet-C6-body f))
	(COMPRESSED-DATA-PACKET                      (build-packet-C8-body f))
	(SYM-ENCR-DATA-PACKET                        (build-packet-C9-body f))
	(LITERAL-DATA-PACKET                         (build-packet-CB-body f))
	(USER-ID-PACKET                              (build-packet-CD-body f))
	(PUBLIC-SUBKEY-PACKET                        (build-packet-C6-body f))
	(otherwise (error "BlackLight OpenPGP does not support the ~A." s))))


;;;
;;; parse-packet-body
;;; takes a packet-type s and a byte list b and returns a field list.
;;;

(defun parse-packet-body (s b)
  (case s
	(PARTIAL-PACKET                              (list b))
	(PKE-SESSION-KEY-PACKET                      (parse-packet-C1-body b))
	(SIGNATURE-PACKET                            (parse-packet-C2-body b))
	(ONE-PASS-SIGNATURE-PACKET                   (parse-packet-C4-body b))
	(PUBLIC-KEY-PACKET                           (parse-packet-C6-body b))
	(COMPRESSED-DATA-PACKET                      (parse-packet-C8-body b))
	(SYM-ENCR-DATA-PACKET                        (parse-packet-C9-body b))
	(LITERAL-DATA-PACKET                         (parse-packet-CB-body b))
	(USER-ID-PACKET                              (parse-packet-CD-body b))
	(PUBLIC-SUBKEY-PACKET                        (parse-packet-C6-body b))
	(otherwise (error "BlackLight OpenPGP does not support the ~A." s))))


;;;
;;; build-packet
;;; takes a nested packet-fields list and returns a flat mssg-bytes list.
;;; Algorithm:
;;;   Make sure that packet-fields is a list.
;;;   Split packet-fields into head-fields and body-fields.
;;;   Call specific build-XX-body with body-fields list.
;;;   It returns a list of body-bytes.
;;;   Append the length of body-bytes list to head-fields list.
;;;   Call build-header with head-fields list.
;;;   It returns a list of head-bytes.
;;;   Return concatenation of head-bytes and body-bytes.
;;;

(defun build-packet (packet-fields)
  (if (not (listp packet-fields)) (error "packet-fields is not a list"))
  (let ((head-fields) (body-fields) (head-bytes) (body-bytes))
    (setf head-fields (subseq packet-fields 0 2))
    (setf body-fields (subseq packet-fields 2 (length packet-fields)))
    (setf body-bytes (build-packet-body (nth 0 head-fields) body-fields))
    (setf head-fields (append head-fields (list (length body-bytes))))
    (setf head-bytes (build-header head-fields))
    (append head-bytes body-bytes)))


;;;
;;; parse-packet
;;; takes a flat mssg-bytes list and returns a list with two values:
;;; a nested packet-fields list and a packet-length integer.
;;; Algorithm:
;;;   Make sure that mssg-bytes is a flat non-empty list of 8-bit integers.
;;;   Call parse-header with mssg-bytes.
;;;   It returns a head-fields list with packet-type, header-type, and body-len.
;;;   Remove header bytes from the front of mssg-bytes.
;;;   Dispatch specific parse-XX-body with shortened mssg-bytes.
;;;   It returns a body-fields list depending on packet-type.
;;;   packet-fields is the concatenation of head-fields and body-fields.
;;;   packet-len is the sum of head-len and body-len.
;;;   Return the two values packet-fields and packet-len.
;;;

(defun parse-packet (mssg-bytes)
  (if (not (blistp mssg-bytes)) (error "mssg-bytes must be a list of bytes."))
  (let ((head-fields) (body-fields) (packet-fields)
	(head-len) (body-len) (packet-len))
    (setf head-fields (parse-header mssg-bytes))
    (setf head-len (header-length (nth 1 head-fields)))
    (setf body-len (nth 2 head-fields)) 
    (setf packet-len (+ head-len body-len))
    (setf body-fields (parse-packet-body (nth 0 head-fields)
	  (subseq mssg-bytes head-len packet-len)))
    (setf packet-fields (append (subseq head-fields 0 2) body-fields))
    (values packet-fields packet-len)))


;;;
;;; packet-vectors
;;; is a list of valid packet lists.
;;;

(defconstant packet-vectors
  '(
    (USER-ID-PACKET OLD-HEADER-2 "Zeta")
    (USER-ID-PACKET OLD-HEADER-3 "Zeta")
    (USER-ID-PACKET OLD-HEADER-5 "Zeta")
    (USER-ID-PACKET OLD-HEADER-I "Zeta")
    (USER-ID-PACKET NEW-HEADER-2 "Zeta")
    (USER-ID-PACKET NEW-HEADER-6 "Zeta")
    (LITERAL-DATA-PACKET OLD-HEADER-3 BINARY-DATA "sargo.com" "2011-Jun-07 10:32:50 UTC"
     (242 253 246 122 47 210 220 141 60 1 144 226 28 199 114 176 201 13 207 166 21 172 71))
    (PUBLIC-KEY-PACKET OLD-HEADER-3 VERSION-4 "2011-Apr-11 15:56:20 UTC" RSA-ENCR-SIGN 
     113887666340268167553174307111356916319933742453335148667744439855039388860191 65537)
    (PUBLIC-SUBKEY-PACKET OLD-HEADER-3 VERSION-4 "2011-Apr-11 15:56:20 UTC" RSA-ENCR-SIGN
     113065716194083540202019425046109962319633505334977557182536995137655781427981 65537)
    (SIGNATURE-PACKET OLD-HEADER-3 VERSION-4 POSITIVE-CERTIFICATION RSA-ENCR-SIGN SHA-1
     ((SUBPACKET-A SIGNATURE-CREATION-TIME "2011-Apr-11 15:56:20 UTC")
      (SUBPACKET-A KEY-FLAGS "101111")
      (SUBPACKET-A PREFERRED-SYMMETRIC-ALGORITHMS AES-256 AES-192 AES-128 CAST5 TRIPLE-DES)
      (SUBPACKET-A PREFERRED-HASH-ALGORITHMS SHA-1 SHA-256 RIPEMD-160)
      (SUBPACKET-A PREFERRED-COMPRESSION-ALGORITHMS ZLIB BZIP2 ZIP)
      (SUBPACKET-A FEATURES "1")
      (SUBPACKET-A KEY-SERVER-PREFERENCES "10000000"))
     ((SUBPACKET-A ISSUER "F894450D1BBE6287"))
     "F8B7" 111348063694709845156432738263881477468424207507875720852842127321331927655311)
    (PKE-SESSION-KEY-PACKET OLD-HEADER-3 VERSION-3 "D6C651468F7D23A1" RSA-ENCR-SIGN 
      115299397691555599139741962953579621188022841546648725058210220916496577642281)
    (SYM-ENCR-DATA-PACKET OLD-HEADER-5
     (129   5 120 219 199  94 188 173 218  16  89  22 230 108  59 109
      182 198 154 107 115  52  34 108 216 250  14  84 240  60 112 178
      254 200 201 175 105 171  44 191 150 188 114 185 230 240  79   3
       52  39 225 204  33 183 117 222 163 239   4 216  31 103  76 254))
    (COMPRESSED-DATA-PACKET OLD-HEADER-3 ZLIB
     ( 97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112
       97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 112))
    (ONE-PASS-SIGNATURE-PACKET OLD-HEADER-3 VERSION-3
     BINARY-SIGNATURE SHA-256 RSA-SIGN-ONLY "FEDCBA9807654321" 0)
    ))


;;;
;;; packet-okayp
;;;

(defun packet-okayp ()
  (let ((x) (y) (z))
    (dotimes (i (length packet-vectors))
      (setf x (nth i packet-vectors))
      (setf y (build-packet x))
      (setf z (parse-packet y))
      (if (not (equal x z))
	  (return-from packet-okayp NIL))))
  T)


