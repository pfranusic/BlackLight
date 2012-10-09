;;;; BlackLight/OpenPGP/comm.lisp
;;;; Copyright 2012 Peter Franusic
;;;;


;;;
;;; comm-encode
;;; takes a communique list and returns an OpenPGP message.
;;; Note: the sender is local, the receiver is remote.
;;;
;;; OpenPGP message:
;;; PKE-SESSION-KEY-PACKET
;;; SYM-ENCR-DATA-PACKET
;;;
;;; Communique list:
;;; 0: symbol, 'COMM
;;; 1: string, creation time in quasi ISO-8601 format
;;; 2: string, user-id of local sender
;;; 3: string, user-id of remote receiver
;;; 4: string, filename
;;; 5: blist, plaintext
;;;

(defun comm-encode (c)
  (let ((m1) (m2) (m3) (h) (ph) (k))

    ;; Check the input.
    (if (not (and (listp c)
		  (= 6 (length c))
		  (symbolp (nth 0 c))
		  (time-stringp (nth 1 c))
		  (stringp (nth 2 c))
		  (stringp (nth 3 c))
		  (stringp (nth 4 c))
		  (blistp (nth 5 c))))
	(error "invalid input list c")
      'okay)

    ;; Initialize m3.
    (setf m3 (copy-list COMM-FORM-3))

    ;; Get the key-hash of the senders's signet key.
    ;; and copy it into the one-pass-signature-packet.
    ;; (comm-encode: local sender, remote receiver).
    (setf (nth 6 (nth 0 m3))
	  (local-signet-hash (nth 2 c)))

    ;; Copy the filename into the literal-data-packet.
    (setf (nth 3 (nth 1 m3))
	  (nth 4 c))

    ;; Put the epoch1970 file time into the literal-data-packet.
    (setf (nth 4 (nth 1 m3))
	  (nth 1 c))

    ;; Copy the plaintext input list into the literal-data-packet.
    (setf (nth 5 (nth 1 m3))
	  (copy-list (nth 5 c)))

    ;; Put an epoch1970 timestamp into the signature-packet.
    (setf (nth 2 (nth 0 (nth 6 (nth 2 m3))))
	  (epoch1970-timestamp))

    ;; Get the sender's signet key-hash into the signature-packet.
    (setf (nth 2 (nth 0 (nth 7 (nth 2 m3))))
	  (nth 6 (nth 0 m3)))

    ;; Compute the sha256-hash over the literal data, etc.
    (sha256-fast-reset)
    (sha256-fast-bytes (nth 5 (nth 1 m3)))
    (sha256-fast-bytes (build-C2-hash (nth 2 m3)))
    (setf h (sha256-fast-hash))

    ;; Put the msw hex-string into the signature-packet.
    (setf (nth 8 (nth 2 m3))
	  (format nil "~4,'0X" (quo h (expt 2 240))))

    ;; Compute the signature using the sender's signet key.
    ;; and put the result into the signature-packet.
    ;; (comm-encode: local sender, remote receiver).
    (setf ph (pkcs-sign-base h
			     (nbytes (local-modulus (nth 6 (nth 0 m3))))
			     'SHA-256))
    (if (not (padded-SHA256-hash-p ph))
	(error "ph is not a padded SHA-256 hash"))
    (setf (nth 9 (nth 2 m3))
	  (modex ph
		 (local-decryptor (nth 6 (nth 0 m3)))   ;; Given a key-id, returns an integer.
		 (local-modulus (nth 6 (nth 0 m3)))))   ;; Given a key-id, returns an integer.

    ;; Initialize m2.
    (setf m2 (copy-list COMM-FORM-2))

    ;; Build m3 and compress it.  Copy the result into the
    ;; compressed data field of the compressed-data-packet.
    (setf (nth 3 (nth 0 m2))
	  (zlib-deflate (build-message m3)))

    ;; Initialize m1.
    (setf m1 (copy-list COMM-FORM-1))

    ;; Get the key-hash for the receiver's cipher key
    ;; and copy it into the pke-session-key-packet.
    ;; (comm-encode: local sender, remote receiver).
    (setf (nth 3 (nth 0 m1))
	  (remote-cipher-hash (nth 3 c)))

    ;; Randomly select a 128-bit session key k.
    ;; Pad the key and encrypt it with the receiver's cipher key.
    ;; Copy the result into the pke-session-key-packet.
    ;; (comm-encode: local sender, remote receiver).
    (setf k (random (expt 2 128)))
    (setf (nth 5 (nth 0 m1))
	  (modex (pkcs-encr-base k
				 (nbytes (remote-modulus (nth 3 (nth 0 m1))))
				 'AES-128)
		 (remote-encryptor (nth 3 (nth 0 m1)))
		 (remote-modulus (nth 3 (nth 0 m1)))))

    ;; Build m2 and encrypt it with the session key and AES-128 in CFB mode.
    ;; Copy the result into the sym-encr-data-packet.
    (setf (nth 2 (nth 1 m1))
	  (cfb-128-encode k nil (build-message m2)))

    ;; Build the m1 message.
    (build-message m1)

    ;; End of comm-encode.
    ))


;;;
;;; decode-session-key
;;; Input is a parsed PKE-SESSION-KEY-PACKET list.
;;; Output is a huge integer, the session key.
;;; Uses a fixed format to keep things simple for now.
;;;

(defun decode-session-key (p)
  (let ((key-id) (psk) (b))

    ;; Check the inputs.
    (if (not (and (listp p)
		  (equal 'PKE-SESSION-KEY-PACKET (nth 0 p))))
	(error "p must be a PKE session key packet"))
    (setf key-id (nth 3 p))
    (if (not (and (hex-stringp key-id)
		  (= 16 (length key-id))))
	(error "Key-ID field is invalid."))

    ;; Decrypt the session key with the receiver's cipher key.
    ;; (comm-decode: remote sender, local receiver).
    (setf psk (modex (nth 5 p)
		     (local-decryptor key-id)
		     (local-modulus key-id)))

    ;; Split psk into a list of bytes b.
    (setf b (split-int 128 psk))

    ;; Check that the format is correct.
    (if (not (and (equal '(0 2) (subseq b 0 2))
		  (equal '(0 7) (subseq b 108 110))))
	(error "session key format is invalid"))

    ;; Verify the checksum.
    (if (/= (checksum (subseq b 110 126))
	    (unite-int (subseq b 126 128)))
	(error "session key has bad checksum"))

    ;; Output the session key.
    (unite-int (subseq b 110 126))

    ;; End decode-session-key.
    ))


;;;
;;; comm-decode
;;; takes an OpenPGP message and returns a communique list.
;;; Note: the sender is remote, the receiver is local.
;;; 
;;; OpenPGP message:
;;; PKE-SESSION-KEY-PACKET
;;; SYM-ENCR-DATA-PACKET
;;;
;;; Communique list:
;;; 0: symbol, 'COMM
;;; 1: string, creation time in quasi ISO-8601 format
;;; 2: string, user-id of remote sender
;;; 3: string, user-id of local receiver
;;; 4: string, filename
;;; 5: blist, plaintext
;;;

(defun comm-decode (b)
  (let ((m1) (m2) (m3) (k) (x) (p) (ph) (htx) (hrx))

    ;; Check the input list.
    (if (not (blistp b))
	(error "b must be a list of bytes"))
    (setf m1 (parse-message b))
    (if (not (and (listp m1)
		  (>= (length m1) 2)
		  (pke-session-key-packet-p (nth 0 m1))
		  (sym-encr-data-packet-p (nth 1 m1))))
	(error "m1 must be a valid GPG communique"))

    ;; Retrieve the session key k.
    (setf k (decode-session-key (nth 0 m1)))

    ;; Build the ciphertext list x and
    ;; decrypt it with k using AES-128 in CFB mode.
    (setf x nil)
    (do ((i 1 (1+ i))) ((>= i (length m1)))
	(setf x (append x (nth 2 (nth i m1)))))
    (setf p (cfb-128-decode k x))

    ;; Parse the resulting plaintext to get m2.
    ;; It should yield a single compressed-data-packet with 
    ;; a ZLIB specifier and list of bytes, the compressed data.
    ;; Check the syntax of this packet.
    (setf m2 (parse-message p))
    (if (not (and (listp m2)
		  (= 1 (length m2))
		  (compressed-data-packet-p (nth 0 m2))))
	(error "m2 is not a valid encapsulated message"))

    ;; Inflate the compressed data in m2 and parse it to get m3.
    ;; It should yield three packets: a one-pass-signature-packet,
    ;; a literal-data-packet, and a binary-signature-packet.
    ;; Check the syntax of each of these packets.
    (setf m3 (parse-message (zlib-inflate (nth 3 (nth 0 m2)))))
    (if (not (and (listp m3)
		  (= 3 (length m3))
		  (one-pass-signature-packet-p (nth 0 m3))
		  (literal-data-packet-p (nth 1 m3))
		  (binary-signature-packet-p (nth 2 m3))))
	(error "m3 is not a valid encapsulated message"))

    ;; Compute the SHA-256 hash hrx over the literal data field
    ;; in the literal-data-packet, and part of the signature-packet.
    ;; Verify the msw in hrx with the msw in the signature-packet.
    (sha256-fast-reset)
    (sha256-fast-bytes (nth 5 (nth 1 m3)))
    (sha256-fast-bytes (build-C2-hash (nth 2 m3)))
    (setf hrx (sha256-fast-hash))
    (if (not (= (quo hrx (expt 2 240))
		(hex-int (nth 8 (nth 2 m3)))))
	(error "msw of hrx NOT EQUAL TO check msw in signature-packet"))

    ;; Decrypt the signature and recover the SHA-256 hash htx.
    ;; Use the Key-ID in the one-pass-signature-packet to get 
    ;; the sender's encryptor and modulus.
    ;; (comm-decode: remote sender, local receiver).
    (setf ph (modex (nth 9 (nth 2 m3))
		    (remote-encryptor (nth 6 (nth 0 m3)))
		    (remote-modulus (nth 6 (nth 0 m3)))))
    (if (not (padded-SHA256-hash-p ph))
	(error "ph is not a padded SHA-256 hash"))
    (setf htx (mod ph (expt 2 256)))

    ;; Verify that the two hashes are equal.
    (if (not (= htx hrx))
	(error "hash htx NOT-EQUAL-TO hash hrx"))

    ;; Generate the output list.
    (list 'COMM                         ; 0: title symbol
	  (nth 4 (nth 1 m3))                ; 1: time string
	  (key-owner (nth 6 (nth 0 m3)))    ; 2: sender string
	  (key-owner (nth 3 (nth 0 m1)))    ; 3: receiver string
	  (nth 3 (nth 1 m3))                ; 4: filename string
	  (nth 5 (nth 1 m3)))               ; 5: plaintext list

    ;; End of comm-decode.
    ))


;;;
;;; comm-okayp
;;; tests comm-encode and comm-decode.
;;; The keyring must contain keys for both Zeta and Zane.
;;;

(defun comm-okayp ()
  (let ((d) (x) (y) (z))
    (setf d (getfile "../Docs/rfc1991.txt"))
    (setf x (list 'COMM (date) "Zeta" "Zane" "rfc1991.txt" d))
    (setf y (comm-encode x))
    (setf z (comm-decode y))
    (equal x z)))

