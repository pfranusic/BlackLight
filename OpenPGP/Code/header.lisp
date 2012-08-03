;;;; BlackLight/OpenPGP/header.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; According to <i>OpenPGP Notes</i> there are eight different packet headers:
;;;; four old headers and four new headers.  Here are the header formats.
;;;; Note that old headers are #x80 through #xBF, new headers are #xC0 through #xFF.
;;;; 
;;;; Header-name    ....0... ....1... ....2... ....3... ....4... ....5...
;;;; old-header-2:  10xxxx00 xxxxxxxx
;;;; old-header-3:  10xxxx01 xxxxxxxx xxxxxxxx
;;;; old-header-5:  10xxxx10 xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
;;;; old-header-I:  10xxxx11
;;;; new-header-2:  11xxxxxx xxxxxxxx
;;;; new-header-3:  11xxxxxx 110xxxxx xxxxxxxx
;;;; new-header-P:  11xxxxxx 111xxxxx
;;;; new-header-6:  11xxxxxx 11111111 xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
;;;; 
;;;; Here are the header predicates. Note that m is the message-list.
;;;; Old header predicates are simpler because the first byte
;;;; completely specifies the format for the rest of the header.
;;;; In new headers, the first and second byte are required
;;;; to specify the rest of the header.
;;;; 
;;;; Header-name    Header-predicate
;;;; old-header-2:  (= #x80 (logand #xC3 (nth 0 m)))
;;;; old-header-3:  (= #x81 (logand #xC3 (nth 0 m)))
;;;; old-header-5:  (= #x82 (logand #xC3 (nth 0 m)))
;;;; old-header-I:  (= #x83 (logand #xC3 (nth 0 m)))
;;;; new-header-2:  (and (= #xC0 (logand #xC0 (nth 0 m)))
;;;;                     (< (nth 1 m) 192)))
;;;; new-header-3:  (and (= #xC0 (logand #xC0 (nth 0 m)))
;;;; 		         (= #xC0 (logand #xE0 (nth 1 m))))
;;;; new-header-P:  (and (= #xC0 (logand #xC0 (nth 0 m)))
;;;; 		         (= #xE0 (logand #xE0 (nth 1 m)))
;;;; 		         (/= #xFF (nth 1 m)))
;;;; new-header-6:  (and (= #xC0 (logand #xC0 (nth 0 m)))
;;;; 		         (= #xFF (nth 1 m)))
;;;; 
;;;; Here are the packet length equations, where m is the message-list.
;;;; The body-length in an old-header-2 is simply the second byte.
;;;; It is more complicated for the other headers.
;;;; Note that what is returned is the total packet length, 
;;;; not just the body length, therefore the length of the header
;;;; must be added to the body length.
;;;; 
;;;; Header-name    packet-length equation
;;;; old-header-2:  (+ 2 (nth 1 m))
;;;; old-header-3:  (+ 3 (unite-int (subseq m 1 3)))
;;;; old-header-5:  (+ 5 (unite-int (subseq m 1 5)))
;;;; old-header-I:  (length m)
;;;; new-header-2:  (+ 2 (nth 1 m))
;;;; new-header-3:  (- (unite-int (subseq m 1 3)) 48957)
;;;; new-header-P:  (+ 2 (expt 2 (logand #x1F (nth 1 m))))
;;;; new-header-6:  (+ 6 (unite-int (subseq m 2 6)))
;;;; 


;;;
;;; *processing-compound-packet*
;;; a boolean variable that indicates a compound-packet is being processed.
;;; Initialized to NIL at boot time.
;;; Set to T at the reception of the first partial packet in a compound-packet.
;;; Set to NIL at the reception of the last partial packet in a compound-packet.
;;;

(defparameter *processing-compound-packet* NIL)


;;;
;;; packet-names-list
;;;

(defconstant *packet-names-list*
  (list
   '(0 PARTIAL-PACKET)
   '(1 PKE-SESSION-KEY-PACKET)
   '(2 SIGNATURE-PACKET)
   '(3 SKE-SESSION-KEY-PACKET)
   '(4 ONE-PASS-SIGNATURE-PACKET)
   '(5 SECRET-KEY-PACKET)
   '(6 PUBLIC-KEY-PACKET)
   '(7 SECRET-SUBKEY-PACKET)
   '(8 COMPRESSED-DATA-PACKET)
   '(9 SYM-ENCR-DATA-PACKET)
   '(10 MARKER-PACKET)
   '(11 LITERAL-DATA-PACKET)
   '(12 TRUST-PACKET)
   '(13 USER-ID-PACKET)
   '(14 PUBLIC-SUBKEY-PACKET)
   '(17 USER-ATTRIBUTE-PACKET)
   '(18 SYM-ENCRYPTED-INTEGRITY-PROTECTED-DATA-PACKET)
   '(19 MODIFICATION-DETECTION-CODE-PACKET)))


;;;
;;; packet-name
;;; given a packet tag number,
;;; returns a symbol that represents the packet name.
;;;

(defun packet-name (tag)
  (if (not (integerp tag)) (error "packet tag must be an integer"))
  (if (or (< tag 1) (> tag 19)) (error "packet tag must be in [1,19]"))
  (dotimes (i (length *packet-names-list*))
    (if (= tag (first (nth i *packet-names-list*)))
	(return-from packet-name (second (nth i *packet-names-list*)))))
  (error "packet tag does not exist"))


;;;
;;; packet-tag
;;; given a symbol that represents a packet name,
;;; returns the packet tag number.
;;;

(defun packet-tag (name)
  (if (not (symbolp name)) (error "packet name must be a symbol"))
  (dotimes (i (length *packet-names-list*))
    (if (equal name (second (nth i *packet-names-list*)))
	(return-from packet-tag (first (nth i *packet-names-list*)))))
  (error "packet name does not exist"))


;;;
;;; header-length
;;; given a header-type symbol, returns the length of the header.
;;; Referenced in packet and message modules.
;;;

(defun header-length (s)
  (case s
	(OLD-HEADER-2         2)
        (OLD-HEADER-3         3)
        (OLD-HEADER-5         5)
        (OLD-HEADER-I         1)
        (NEW-HEADER-2         2)
        (NEW-LENGTH-1         1)
        (NEW-HEADER-3         3)
        (NEW-LENGTH-2         2)
        (NEW-HEADER-P         2)
        (NEW-LENGTH-P         1)
        (NEW-HEADER-6         6)
        (NEW-LENGTH-5         5)
	(otherwise (error "header type ~A does not exist" s))))


;;;
;;; build-header
;;; takes a list h containing the packet-type, the header-type, and the body-length, 
;;; and returns a list y of bytes containing the packet-tag, the body-length-header, and ...
;;;

(defun build-header (h)
  (if (not (listp h)) (error "h is not a list"))
  (if (not (= 3 (length h))) (error "list h does not have 3 elements"))
  (if (not (symbolp (nth 0 h))) (error "h[0] is not a symbol"))
  (if (not (symbolp (nth 1 h))) (error "h[1] is not a symbol"))
  (if (not (integerp (nth 2 h))) (error "h[2] is not an integer"))
  (let ((packet-type (packet-tag (nth 0 h)))
	(header-type (nth 1 h))
	(body-length (nth 2 h)))
    (case header-type
	  (OLD-HEADER-2  (progn
			   (if (not (and (<= 0 body-length)
					 (<= body-length 255)))
			       (error "body-length not in [0,255]"))
			   (append (list (logior #x80 (* 4 packet-type)))
				   (list body-length))))
	  (OLD-HEADER-3  (progn
			   (if (not (and (<= 0 body-length)
					 (<= body-length 65535)))
			       (error "body-length not in [0,65535]"))
			   (append (list (logior #x81 (* 4 packet-type)))
				   (split-int 2 body-length))))
	  (OLD-HEADER-5  (progn
			   (if (not (and (<= 0 body-length)
					 (<= body-length 4294967295)))
			       (error "body-length not in [0,4294967295]"))
			   (append (list (logior #x82 (* 4 packet-type)))
				   (split-int 4 body-length))))
	  (OLD-HEADER-I  (progn
			   (list (logior #x83 (* 4 packet-type)))))
	  (NEW-HEADER-2  (progn
			   (if (not (and (<= 0 body-length)
					 (<= body-length 191)))
			       (error "body-length not in [0,191]"))
			   (append (list (logior #xC0 packet-type))
				   (list body-length))))
	  (NEW-LENGTH-1  (progn
			   (if (not (and (<= 0 body-length)
					 (<= body-length 191)))
			       (error "body-length not in [0,191]"))
			   (list body-length)))
	  (NEW-HEADER-3  (progn
			   (if (not (and (<= 192 body-length)
					 (<= body-length 8383)))
			       (error "body-length not in [192,8383]"))
			   (append (list (logior #xC0 packet-type))
				   (split-int 2 (+ 48960 body-length)))))
	  (NEW-LENGTH-2  (progn
			   (if (not (and (<= 192 body-length)
					 (<= body-length 8383)))
			       (error "body-length not in [192,8383]"))
			   (split-int 2 (+ 48960 body-length))))
	  (NEW-HEADER-P  (progn
			   (list (logior #xC0 packet-type)
				 (logior #xE0 (round (log body-length 2))))))
	  (NEW-LENGTH-P  (progn
			   (list (logior #xE0 (round (log body-length 2))))))
	  (NEW-HEADER-6  (progn
			   (if (not (and (<= 0 body-length)
					 (<= body-length 4294967295)))
			       (error "body-length not in [0,4294967295]"))
			   (append (list (logior #xC0 packet-type))
				   (list #xFF)
				   (split-int 4 body-length))))
	  (NEW-LENGTH-5  (progn
			   (append (list #xFF)
				   (split-int 4 body-length))))
	  (otherwise     (error "header-type ~A not found" header-type)))))


;;;
;;; parse-header
;;; takes a message list m and returns a list containing
;;; the packet-type, the header-type, and the body-length.
;;;

(defun parse-header (m)
  (if (not (listp m)) (error "m is not a list"))
  ;-------------------------------------------------------------------
  ; OLD-HEADER-2
  (if (= #x80 (logand #xC3 (nth 0 m)))
      (return-from parse-header
		   (list (packet-name (/ (logand #x3C (nth 0 m)) 4))
			 'OLD-HEADER-2
			 (nth 1 m))))
  ;-------------------------------------------------------------------
  ; OLD-HEADER-3
  (if (= #x81 (logand #xC3 (nth 0 m)))
      (return-from parse-header
		   (list (packet-name (/ (logand #x3C (nth 0 m)) 4))
			 'OLD-HEADER-3
			 (unite-int (subseq m 1 3)))))
  ;-------------------------------------------------------------------
  ; OLD-HEADER-5
  (if (= #x82 (logand #xC3 (nth 0 m)))
      (return-from parse-header
		   (list (packet-name (/ (logand #x3C (nth 0 m)) 4))
			 'OLD-HEADER-5
			 (unite-int (subseq m 1 5)))))
  ;-------------------------------------------------------------------
  ; OLD-HEADER-I
  (if (= #x83 (logand #xC3 (nth 0 m)))
      (return-from parse-header
		   (list (packet-name (/ (logand #x3C (nth 0 m)) 4))
			 'OLD-HEADER-I
			 (1- (length m)))))
  ;-------------------------------------------------------------------
  ; NEW-HEADER-2
  (if (and (not *processing-compound-packet*)
	   (= #xC0 (logand #xC0 (nth 0 m)))
	   (< (nth 1 m) 192))
      (progn 
	(return-from parse-header
		     (list (packet-name (logand #x3F (nth 0 m)))
			   'NEW-HEADER-2
			   (nth 1 m)))))
  ;-------------------------------------------------------------------
  ; NEW-LENGTH-1
  (if (and *processing-compound-packet*
	   (< (nth 0 m) 192))
      (progn
	(setf *processing-compound-packet* NIL)
	(return-from parse-header
		     (list 'PARTIAL-PACKET
			   'NEW-LENGTH-1
			   (nth 0 m)))))
  ;-------------------------------------------------------------------
  ; NEW-HEADER-3
  (if (and (not *processing-compound-packet*)
	   (= #xC0 (logand #xC0 (nth 0 m)))
	   (= #xC0 (logand #xE0 (nth 1 m))))
      (progn
	(return-from parse-header
		     (list (packet-name (logand #x3F (nth 0 m)))
			   'NEW-HEADER-3
			   (- (unite-int (subseq m 1 3)) 48960)))))
  ;-------------------------------------------------------------------
  ; NEW-LENGTH-2
  (if (and *processing-compound-packet*
	   (= #xC0 (logand #xE0 (nth 0 m))))
      (progn
	(setf *processing-compound-packet* NIL)
	(return-from parse-header
		     (list 'PARTIAL-PACKET
			   'NEW-LENGTH-2
			   (- (unite-int (subseq m 0 2)) 48960)))))
  ;-------------------------------------------------------------------
  ; NEW-HEADER-P
  (if (and (not *processing-compound-packet*)
	   (= #xC0 (logand #xC0 (nth 0 m)))
	   (= #xE0 (logand #xE0 (nth 1 m)))
	   (not (= #xFF (nth 1 m))))
      (progn
	(setf *processing-compound-packet* T)
	(return-from parse-header
		     (list (packet-name (logand #x3F (nth 0 m)))
			   'NEW-HEADER-P
			   (expt 2 (logand #x1F (nth 1 m)))))))
  ;-------------------------------------------------------------------
  ; NEW-LENGTH-P
  (if (and *processing-compound-packet*
	   (= #xE0 (logand #xE0 (nth 0 m)))
	   (not (= #xFF (nth 0 m))))
      (progn
	(return-from parse-header
		     (list 'PARTIAL-PACKET
			   'NEW-LENGTH-P
			   (expt 2 (logand #x1F (nth 0 m)))))))
  ;-------------------------------------------------------------------
  ; NEW-HEADER-6
  (if (and (not *processing-compound-packet*)
	   (= #xC0 (logand #xC0 (nth 0 m)))
	   (= #xFF (nth 1 m)))
      (progn
	(return-from parse-header
		     (list (packet-name (logand #x3F (nth 0 m)))
			   'NEW-HEADER-6
			   (unite-int (subseq m 2 6))))))
  ;-------------------------------------------------------------------
  ; NEW-LENGTH-5 (last partial packet)
  (if (and *processing-compound-packet*
	   (= #xFF (nth 0 m)))
      (progn
	(setf *processing-compound-packet* NIL)
	(return-from parse-header
		     (list 'PARTIAL-PACKET
			   'NEW-LENGTH-5
			   (unite-int (subseq m 1 5))))))
  ;-------------------------------------------------------------------
  (error "not able to parse bytes" (car m)))


;;;
;;; header-vectors
;;; This is a list of test vectors for header-okayp.
;;; Each vector is a list consisting of 
;;; a symbol that represents the packet type,
;;; a symbol that represents the header type, and
;;; an integer that represents the length of the packet body.
;;;

(defconstant header-vectors
  (list 
   (list 'LITERAL-DATA-PACKET 'OLD-HEADER-2 0)
   (list 'LITERAL-DATA-PACKET 'OLD-HEADER-2 255)
   (list 'LITERAL-DATA-PACKET 'OLD-HEADER-3 0)
   (list 'LITERAL-DATA-PACKET 'OLD-HEADER-3 65535)
   (list 'LITERAL-DATA-PACKET 'OLD-HEADER-5 0)
   (list 'LITERAL-DATA-PACKET 'OLD-HEADER-5 4294967295)
   (list 'LITERAL-DATA-PACKET 'NEW-HEADER-2 0)
   (list 'LITERAL-DATA-PACKET 'NEW-HEADER-2 191)
   (list 'LITERAL-DATA-PACKET 'NEW-HEADER-3 192)
   (list 'LITERAL-DATA-PACKET 'NEW-HEADER-3 8383)
   (list 'LITERAL-DATA-PACKET 'NEW-HEADER-6 0)
   (list 'LITERAL-DATA-PACKET 'NEW-HEADER-6 4294967295)
   (list 'PKE-SESSION-KEY-PACKET 'OLD-HEADER-2 251)
   (list 'SIGNATURE-PACKET 'OLD-HEADER-3 4001)
   (list 'ONE-PASS-SIGNATURE-PACKET 'OLD-HEADER-5 1234567)
   (list 'PUBLIC-KEY-PACKET 'NEW-HEADER-2 187)
   (list 'COMPRESSED-DATA-PACKET 'NEW-HEADER-3 5791)
   (list 'SYM-ENCR-DATA-PACKET 'NEW-HEADER-P 65536)
   (list 'PARTIAL-PACKET 'NEW-LENGTH-P 65536)
   (list 'PARTIAL-PACKET 'NEW-LENGTH-P 65536)
   (list 'PARTIAL-PACKET 'NEW-LENGTH-2 5791)
   (list 'USER-ID-PACKET 'NEW-HEADER-2 37)
   ))


;;;
;;; header-okayp
;;; tests build-header and parse-header.
;;;

(defun header-okayp ()
  (let ((x) (y) (z))
    (dotimes (i (length header-vectors))
      (setf x (nth i header-vectors))
      (setf y (build-header x))
      (setf z (parse-header y))
      (if (not (equal x z))
	  (return-from header-okayp NIL)))
    T))


