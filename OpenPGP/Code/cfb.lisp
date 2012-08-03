;;;; BlackLight/OpenPGP/cfb.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; aes-expand-128
;;;; takes a 128-bit key integer k
;;;; and returns a key-schedule vector w.
;;;; The key-schedule consists of forty-four 32-bit words
;;;; that are derived from the session key.
;;;; ? (setf k (random (expt 2 128)))
;;;; ? (setf w (aes-expand-128 k))
;;;;
;;;; aes-cipher-128
;;;; returns ciphertext given key-schedule w and plaintext p.
;;;; w is a vector of 44 32-bit integers.
;;;; The plaintext p and ciphertext are each a 128-bit integer.
;;;; ? (setf p (random (expt 2 128)))
;;;; ? (setf c (aes-cipher-128 w p))
;;;;


;;;
;;; cfb-encode-128
;;; Input is a 128-bit session key integer k
;;; and a list of plaintext bytes p-list.
;;; Output is a list of ciphertext bytes c-list.
;;; Expands the session key k into a 44-word key schedule,
;;; performs the AES-128 Cipher function in OpenPGP CFB Mode
;;; on all bytes in p-list, and returns c-list.
;;;

(defun cfb-encode-128 (k p-list)
  (let ((w) (f) (n) (r-list) (c-list))
    
    ;;; Step A:
    ;;; Make sure the inputs are okay.
    ;;; Create key schedule w from session key k.
    ;;; Create r-list with 16 random byte values.
    (if (not (and (integerp k) (plusp k) (< (log k 2) 128)))
	(error "k must be a positive integer less than 2^128"))
    (if (not (blistp p-list))
	(error "p-list must be a non-empty list of bytes"))
    (setf w (aes-expand-128 k))
    (setf r-list (random-bytes 16))

    ;;; Step B:
    ;;; Compute the 128-bit integer $r_i$ from r-list.
    ;;; Compute the 128-bit integer $c_{-2} = aes(0) + r_i$
    ;;; Split $c_{-2}$ into 16 bytes and initialize c-list.
    (setf f (logxor (aes-cipher-128 w 0)
		    (unite-int r-list)))
    (setf c-list (split-int 16 f))

    ;;; Step C:
    ;;; Compute the 16-bit integer $r_q$ from (subseq r-list 14 16).
    ;;; Compute the 16-bit integer $c_q = msw(aes(c_{-2})) + r_q$.
    ;;; Split $c_q$ into 2 bytes and append them to c-list.
    (setf f (logxor (quo (aes-cipher-128 w f) (expt 2 112))
		    (unite-int (subseq r-list 14 16))))
    (setf c-list (append c-list (split-int 2 f)))

    ;;; Step D:
    ;;; Construct the 128-bit integer $c_{-1}$ from (subseq c 2 18).
    (setf f (unite-int (subseq c-list 2 18)))

    ;;; Step E:
    ;;; While there are at least 16 bytes in p-list:
    ;;; Compute the 128-bit integer $p_i$ from the next 16 bytes in p-list.
    ;;; Compute the 128-bit integer $c_i = aes(c_{i-1}) + p_i$
    ;;; Split $c_i$ into 16 bytes and append them to c-list.
    ;;; Remove 16 bytes from p-list.
    (while (>= (length p-list) 16)
      (setf f (logxor (aes-cipher-128 w f)
		      (unite-int (subseq p-list 0 16))))
      (setf c-list (append c-list (split-int 16 f)))
      (dotimes (i 16) (pop p-list)))

    ;;; Step F:
    ;;; If p-list is not empty:
    ;;; Let n be the number of remaining bytes in p-list.
    ;;; Compute the 128-bit integer $p_i$ from the remaining n bytes,
    ;;; trailed by (- 16 n) dummy bytes in the least-significant bits.
    ;;; Compute the 128-bit integer $c_i = aes(c_{i-1}) + p_i$.
    ;;; Split $c_i$ into 16 bytes and append the first n bytes to c-list.
    ;;; Remove n bytes from p-list.
    (while (> (setf n (length p-list)) 0)
      (setf f (logxor (aes-cipher-128 w f)
		      (unite-int (append p-list (listn (- 16 n) 0)))))
      (setf c-list (append c-list (subseq (split-int 16 f) 0 n)))
      (dotimes (i n) (pop p-list)))

    ;;; Step G:
    ;;; Return c-list.
    c-list))


;;;
;;; cfb-decode-128
;;; Input is a 128-bit session key integer k 
;;; and a list of ciphertext bytes c-list.
;;; Output is a list of plaintext bytes p-list.
;;; Expands the session key k into a 44-word key schedule,
;;; performs the AES-128 Cipher function in OpenPGP CFB Mode
;;; on all bytes in c-list, and returns p-list.
;;;

(defun cfb-decode-128 (k c-list)
  (let ((w) (f) (n) (c_i) (p_i) (p-list))

    ;;; Step A:
    ;;; Make sure the inputs are okay.
    ;;; Create key schedule w from session key k.
    (if (not (and (integerp k) (plusp k) (< (log k 2) 128)))
	(error "k must be a positive integer less than 2^128"))
    (if (not (and (blistp c-list) (>= (length c-list) 18)))
	(error "c-list must be a list of bytes with at least 18 elements"))
    (setf w (aes-expand-128 k))

    ;;; Step D:
    ;;; Compute the 128-bit integer $c_{-1}$ from (subseq c 2 18).
    ;;; Remove 18 bytes from c-list.
    (setf c_i (unite-int (subseq c-list 2 18)))
    (dotimes (i 18) (pop c-list))

    ;;; Step E:
    ;;; While there are at least 16 bytes in c-list:
    ;;; Compute the 128-bit integer $c_i$ from the next 16 bytes in c-list.
    ;;; Compute the 128-bit integer $p_i = aes(c_{i-1}) + c_i$.
    ;;; Split $p_i$ into 16 bytes and append them to p-list.
    ;;; Remove 16 bytes from c-list.
    (while (>= (length c-list) 16)
      (setf f c_i) ; Set feedback register to previous $c_i$.
      (setf c_i (unite-int (subseq c-list 0 16)))
      (setf p_i (logxor (aes-cipher-128 w f) c_i))
      (setf p-list (append p-list (split-int 16 p_i)))
      (dotimes (i 16) (pop c-list)))

    ;;; Step F:
    ;;; While c-list is not empty:
    ;;; Let n be the number of remaining bytes in c-list.
    ;;; Compute the 128-bit integer $c_i$ from the remaining n bytes,
    ;;; trailed by (- 16 n) dummy bytes in the least-significant bits.
    ;;; Compute the 128-bit integer $p_i = aes(c_{i-1}) + c_i$.
    ;;; Split $p_i$ into 16 bytes and append the first n bytes to p-list.
    ;;; Remove n bytes from c-list.
    (while (> (setf n (length c-list)) 0)
      (setf f c_i)
      (setf c_i (unite-int (append (subseq c-list 0 n) (listn (- 16 n) 0))))
      (setf p_i (logxor (aes-cipher-128 w f) c_i))
      (setf p-list (append p-list (subseq (split-int 16 p_i) 0 n)))
      (dotimes (i 16) (pop c-list)))

    ;;; Step G:
    ;;; Return p-list.
    p-list))


;;;
;;; cfb-okayp
;;; tests the aes-128-cfb function.
;;;

(defun cfb-okayp ()
  (let ((k) (x) (y) (z))
    (setf k (random (expt 2 128)))
    (setf x (random-bytes (+ 100 (random 16))))
    (setf y (cfb-encode-128 k x))
    (setf z (cfb-decode-128 k y))
    (equal x z)))


