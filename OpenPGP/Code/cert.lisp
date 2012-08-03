;;;; BlackLight/OpenPGP/cert.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; Lisp code to generate gpg5 certificates.
;;;; 
;;;; gpg5-cert-form:  This is the form for a gpg5 certificate.
;;;; pgp-key-id returns the lower 16 digits of a V4 fingerprint.
;;;; gpg5-cert-p returns T iff m is a valid gpg5 certificate.
;;;; build-C6-hash returns the byte list of a C6 packet list.
;;;; build-CD-hash returns the byte list of a CD packet list.
;;;; build-C2-hash returns the byte list of a C2 packet list.
;;;; gpg5-hash-1 returns the SHA1 hash for the 1st signature in a gpg5 cert.
;;;; gpg5-hash-2 returns the SHA1 hash for the 2nd signature in a gpg5 cert.
;;;; gpg5-hash-3 returns the SHA1 hash for the 3rd signature in a gpg5 cert.
;;;; gpg5-hash-msw-1 returns the Hash MSW for the 1st signature in a gpg5 cert.
;;;; gpg5-hash-msw-2 returns the Hash MSW for the 2nd signature in a gpg5 cert.
;;;; gpg5-hash-msw-3 returns the Hash MSW for the 3rd signature in a gpg5 cert.
;;;; gpg5-verified-p returns T iff the certicate c has been verified.
;;;; gpg5-export translates a list of two local keys to a gpg5 certificate list.
;;;; gpg5-import translates a gpg5 certificate list to a list of two remote keys.
;;;; cert-export translates a local keyfile into a gpg5 certificate file.
;;;; cert-import translates a gpg5 certificate file into a remote keyfile.
;;;; cert-okayp tests the cert-export and cert-import functions.


;;;
;;; gpg5-cert-form
;;; This is the form for a gpg5 certificate.
;;; The "holes" are marked with a ";####" followed by
;;; an access expression and a source tag.
;;;

(defconstant gpg5-cert-form
  '((PUBLIC-KEY-PACKET
     OLD-HEADER-3
     VERSION-4
     "XXXX-XXX-XX XX:XX:XX UTC"                   ;#### (nth 3 (nth 0 c))  ; ktp
     RSA-ENCR-SIGN
     9999999999999999999999999999999999999999     ;#### (nth 5 (nth 0 c))  ; vn
     999999999999999999999999999999999999999)     ;#### (nth 6 (nth 0 c))  ; ve
    (USER-ID-PACKET
     OLD-HEADER-3
     "xxx xxxx <xxxx@xxxxx.xxx>")                 ;#### (nth 2 (nth 1 c))  ; ui
    (SIGNATURE-PACKET
     OLD-HEADER-3
     VERSION-4
     POSITIVE-CERTIFICATION
     RSA-ENCR-SIGN
     SHA-1                              ;#### (nth 5 (nth 2 m))  ; alg1
     ((SUBPACKET-A
       SIGNATURE-CREATION-TIME
       "XXXX-XXX-XX XX:XX:XX UTC")      ;#### (nth 2 (nth 0 (nth 6 (nth 2 c))))  ; st1
      (SUBPACKET-A
       KEY-FLAGS
       "101111")
      (SUBPACKET-A
       PREFERRED-SYMMETRIC-ALGORITHMS
       AES-256 AES-192 AES-128)
      (SUBPACKET-A
       PREFERRED-HASH-ALGORITHMS
       SHA-1 SHA-256)
      (SUBPACKET-A
       PREFERRED-COMPRESSION-ALGORITHMS
       ZLIB)
      (SUBPACKET-A
       FEATURES
       "1")
      (SUBPACKET-A
       KEY-SERVER-PREFERENCES
       "10000000"))
     ((SUBPACKET-A 
       ISSUER
       "FFFFFFFFFFFFFFFF"))                       ;#### (nth 2 (nth 0 (nth 7 (nth 2 c))))  ; kid1
     "FFFF"                                       ;#### (nth 8 (nth 2 c))  ; msw1
     9999999999999999999999999999999999999999)    ;#### (nth 9 (nth 2 c))  ; sig1
    (PUBLIC-SUBKEY-PACKET
     OLD-HEADER-3
     VERSION-4
     "XXXX-XXX-XX XX:XX:XX UTC"                   ;#### (nth 3 (nth 3 c))  ; kts
     RSA-ENCR-SIGN
     9999999999999999999999999999999999999999     ;#### (nth 5 (nth 3 c))  ; cn
     999999999999999999999999999999999999999)     ;#### (nth 6 (nth 3 c))  ; ce
    (SIGNATURE-PACKET
     OLD-HEADER-3
     VERSION-4
     SUBKEY-BINDING-SIGNATURE
     RSA-ENCR-SIGN
     SHA-1                              ;#### (nth 5 (nth 4 m))  ; alg2
     ((SUBPACKET-A
       SIGNATURE-CREATION-TIME
       "XXXX-XXX-XX XX:XX:XX UTC")      ;#### (nth 2 (nth 0 (nth 6 (nth 4 c))))  ; st2
      (SUBPACKET-A
       KEY-FLAGS
       "101110"))
     ((SUBPACKET-A
       ISSUER
       "FFFFFFFFFFFFFFFF")              ;#### (nth 2 (nth 0 (nth 7 (nth 4 c))))  ; kid2
      (SUBPACKET-A
       EMBEDDED-SIGNATURE
       VERSION-4
       PRIMARY-KEY-BINDING-SIGNATURE
       RSA-ENCR-SIGN
       SHA-1                             ;#### (nth 5 (nth 1 (nth 7 (nth 4 c))))  ; alg3
       ((SUBPACKET-A
	 SIGNATURE-CREATION-TIME
	 "XXXX-XXX-XX XX:XX:XX UTC"))  ;#### (nth 2 (nth 0 (nth 6 (nth 1 (nth 7 (nth 4 c))))))  ; st3
       ((SUBPACKET-A 
	 ISSUER
	 "FFFFFFFFFFFFFFFF"))          ;#### (nth 2 (nth 0 (nth 7 (nth 1 (nth 7 (nth 4 c))))))  ; kid3
       "FFFF"                                          ;#### (nth 8 (nth 1 (nth 7 (nth 4 c))))  ; msw3
       9999999999999999999999999999999999999999))      ;#### (nth 9 (nth 1 (nth 7 (nth 4 c))))  ; sig3
     "FFFF"                                         ;#### (nth 8 (nth 4 c))  ; msw2
     9999999999999999999999999999999999999999)))    ;#### (nth 9 (nth 4 c))  ; sig2


;;;
;;;
;;; pgp-key-id
;;; returns the lower 16 digits of a V4 fingerprint.
;;; Input is a Public-Key packet or a Public-Subkey packet.
;;;

(defun pgp-key-id (p)
  (format nil "~16,'0X" 
	  (mod (v4-fingerprint p)
	       (expt 2 64))))


;;;
;;; gpg5-cert-p
;;; returns T iff m is a valid gpg5 certificate.
;;; A gpg5 certificate contains the following five packets, in order:
;;; a Public-Key packet, a User-ID packet,
;;; a Signature packet, a Public-Subkey packet, and
;;; a Signature packet with an Embedded Signature subpacket.
;;;

(defun gpg5-cert-p (m)
  (and (listp m)
       (= 5 (length m))

       (listp (nth 0 m))
       (equal 'PUBLIC-KEY-PACKET (nth 0 (nth 0 m)))
       (equal 'VERSION-4 (nth 2 (nth 0 m)))
       (time-stringp (nth 3 (nth 0 m)))
       (equal 'RSA-ENCR-SIGN (nth 4 (nth 0 m)))
       (integerp (nth 5 (nth 0 m)))
       (integerp (nth 6 (nth 0 m)))
       (in-between 511 (log (nth 5 (nth 0 m)) 2) 8193)

       (listp (nth 1 m))
       (equal 'USER-ID-PACKET (nth 0 (nth 1 m)))
       (stringp (nth 2 (nth 1 m)))
       (> (length (nth 2 (nth 1 m))) 0)

       (listp (nth 2 m))
       (equal 'SIGNATURE-PACKET (nth 0 (nth 2 m)))
       (equal 'VERSION-4 (nth 2 (nth 2 m)))
       (equal 'POSITIVE-CERTIFICATION (nth 3 (nth 2 m)))
       (equal 'RSA-ENCR-SIGN (nth 4 (nth 2 m)))
       (equal 'SHA-1 (nth 5 (nth 2 m)))
       (equal 'ISSUER (nth 1 (nth 0 (nth 7 (nth 2 m)))))
       (equal (nth 2 (nth 0 (nth 7 (nth 2 m)))) (pgp-key-id (nth 0 m)))
       (equal (gpg5-hash-msw-1 m) (nth 8 (nth 2 m)))
       (integerp (nth 9 (nth 2 m)))
       (in-between 511 (log (nth 9 (nth 2 m)) 2) 8193)

       (listp (nth 3 m))
       (equal 'PUBLIC-SUBKEY-PACKET (nth 0 (nth 3 m)))
       (equal 'VERSION-4 (nth 2 (nth 3 m)))
       (time-stringp (nth 3 (nth 3 m)))
       (equal 'RSA-ENCR-SIGN (nth 4 (nth 3 m)))
       (integerp (nth 5 (nth 3 m)))
       (integerp (nth 6 (nth 3 m)))
       (in-between 511 (log (nth 5 (nth 3 m)) 2) 8193)

       (listp (nth 4 m))
       (equal 'SIGNATURE-PACKET (nth 0 (nth 4 m)))
       (equal 'VERSION-4 (nth 2 (nth 4 m)))
       (equal 'SUBKEY-BINDING-SIGNATURE (nth 3 (nth 4 m)))
       (equal 'RSA-ENCR-SIGN (nth 4 (nth 4 m)))
       (equal 'SHA-1 (nth 5 (nth 4 m)))
       (equal 'ISSUER (nth 1 (nth 0 (nth 7 (nth 4 m)))))
       (equal (nth 2 (nth 0 (nth 7 (nth 4 m)))) (pgp-key-id (nth 0 m)))
       (equal (gpg5-hash-msw-2 m) (nth 8 (nth 4 m)))
       (integerp (nth 9 (nth 4 m)))
       (in-between 511 (log (nth 9 (nth 4 m)) 2) 8193)
       ))


;;;
;;; build-C6-hash
;;; returns the byte list of a C6 packet list.
;;; This can be used to compute the hash for a signature.
;;;

(defun build-C6-hash (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (not (= 7 (length f))) (error "list f must have 7 elements"))
  (if (not (symbolp  (nth 0 f))) (error "packet-type must be a symbol"))
  (if (not (symbolp  (nth 1 f))) (error "header-type must be a symbol"))
  (if (not (symbolp  (nth 2 f))) (error "version-no must be a symbol"))
  (if (not (stringp  (nth 3 f))) (error "key-time must be a string"))
  (if (not (symbolp  (nth 4 f))) (error "pub-key-alg must be a symbol"))
  (if (not (integerp (nth 5 f))) (error "mpi-int must be an integer"))
  (if (not (integerp (nth 6 f))) (error "mpi-int must be an integer"))
  (let ((g (copy-list f)))
    (setf (nth 0 g) 'PUBLIC-KEY-PACKET)
    (setf (nth 1 g) 'OLD-HEADER-3)
    (build-packet g)))


;;;
;;; build-CD-hash
;;; returns the byte list of a CD packet list.
;;; This can be used to compute the hash for a signature.
;;;

(defun build-CD-hash (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (not (= 3 (length f))) (error "list f must have 10 elements"))
  (if (not (symbolp (nth 0 f))) (error "packet-type must be a symbol"))
  (if (not (symbolp (nth 1 f))) (error "header-type must be a symbol"))
  (if (not (stringp (nth 2 f))) (error "user-id must be a string"))
  (let ((user-id (split-str (nth 2 f))))
    (append (list #xB4) (split-int 4 (length user-id)) user-id)))


;;;
;;; build-C2-hash
;;; returns the byte list of a C2 packet list.
;;; This can be used to compute the hash for a V4 signature.
;;; See RFC-4880 section 5.2.4 "Computing Signatures".
;;;

(defun build-C2-hash (f)
  (if (not (listp f)) (error "f must be a list"))
  (if (not (= 10 (length f))) (error "list f must have 10 elements"))
  (if (not (symbolp (nth 0 f))) (error "packet-type must be a symbol"))
  (if (not (symbolp (nth 1 f))) (error "header-type must be a symbol"))
  (if (not (symbolp (nth 2 f))) (error "version-no must be a symbol"))
  (if (not (symbolp (nth 3 f))) (error "signet-type must be a symbol"))
  (if (not (symbolp (nth 4 f))) (error "pub-key-alg must be a symbol"))
  (if (not (symbolp (nth 5 f))) (error "hash-alg must be a symbol"))
  (if (not (listp   (nth 6 f))) (error "hashed-subs must be a list"))
  (let ((hashed-subs) (b))
    (setf hashed-subs (build-subpacket-block (nth 6 f)))
    (setf b (append (list (version-type-code (nth 2 f)))
		    (list (signature-type-code (nth 3 f)))
		    (list (public-key-algorithm-code (nth 4 f)))
		    (list (hash-algorithm-code (nth 5 f)))
		    (split-int 2 (length hashed-subs))
		    hashed-subs))
    (append b (list #x04 #xFF) (split-int 4 (length b)))))


;;;
;;; gpg5-hash-1
;;; returns the SHA1 hash for the 1st signature in a gpg5 certificate.
;;;

(defun gpg5-hash-1 (m)
  (sha1-reset)
  (sha1-bytes (build-C6-hash (nth 0 m)))
  (sha1-bytes (build-CD-hash (nth 1 m)))
  (sha1-bytes (build-C2-hash (nth 2 m)))
  (sha1-hash))


;;;
;;; gpg5-hash-2
;;; returns the SHA1 hash for the 2nd signature in a gpg5 certificate.
;;;

(defun gpg5-hash-2 (m)
  (sha1-reset)
  (sha1-bytes (build-C6-hash (nth 0 m)))
  (sha1-bytes (build-C6-hash (nth 3 m)))
  (sha1-bytes (build-C2-hash (nth 4 m)))
  (sha1-hash))


;;;
;;; gpg5-hash-3
;;; returns the SHA1 hash for the 3rd signature in a gpg5 certificate.
;;;

(defun gpg5-hash-3 (m)
  (sha1-reset)
  (sha1-bytes (build-C6-hash (nth 0 m)))
  (sha1-bytes (build-C6-hash (nth 3 m)))
  (sha1-bytes (build-C2-hash (nth 1 (nth 7 (nth 4 m)))))
  (sha1-hash))


;;;
;;; gpg5-hash-msw-1
;;; returns the Hash MSW for the 1st signature in a gpg5 certificate.
;;;

(defun gpg5-hash-msw-1 (m)
  (let ((h (gpg5-hash-1 m)))
    (format nil "~4,'0X" (quo h (expt 2 144)))))


;;;
;;; gpg5-hash-msw-2
;;; returns the Hash MSW for the 2nd signature in a gpg5 certificate.
;;;

(defun gpg5-hash-msw-2 (m)
  (let ((h (gpg5-hash-2 m)))
    (format nil "~4,'0X" (quo h (expt 2 144)))))


;;;
;;; gpg5-hash-msw-3
;;; returns the Hash MSW for the 3rd signature in a gpg5 certificate.
;;;

(defun gpg5-hash-msw-3 (m)
  (let ((h (gpg5-hash-3 m)))
    (format nil "~4,'0X" (quo h (expt 2 144)))))


;;;
;;; gpg5-verified-p
;;; returns T iff the certicate c has been verified.
;;;

(defun gpg5-verified-p (m)

  (and (= (modex (nth 9 (nth 2 m))                              ; sig1
		 (nth 6 (nth 0 m))                              ; ve
		 (nth 5 (nth 0 m)))                             ; vn
	  (pkcs-sign-base (gpg5-hash-1 m)                       ;#### TEMPORARY ####
			(nbytes (nth 5 (nth 0 m)))              ; vn
			(nth 5 (nth 2 m))))                     ; alg1

       (= (modex (nth 9 (nth 4 m))                              ; sig2
		 (nth 6 (nth 0 m))                              ; ve
		 (nth 5 (nth 0 m)))                             ; vn
	  (pkcs-sign-base (gpg5-hash-2 m)                       ;#### TEMPORARY ####
			(nbytes (nth 5 (nth 0 m)))              ;
			(nth 5 (nth 4 m))))                     ; alg2
       ))


;;;
;;; gpg5-export
;;; translates a list of two local keys to a gpg5 certificate list.
;;; Input is a list of two RSA keys: RSA-LS and RSA-LC.
;;; Output is a field list containing a certificate.
;;; The strategy is to copy a form and fill in the holes.
;;; (See gpg5-cert-form above). There are 19 holes in all.
;;; PUBLIC-KEY-PACKET:     ktp  vn   ve
;;; USER-ID-PACKET:        ui
;;; 1st SIGNATURE-PACKET:  st1  kid1  msw1  sig1
;;; PUBLIC-SUBKEY-PACKET:  kts  cn   ce
;;; 2nd SIGNATURE-PACKET:  st2  kid2  msw2  sig2
;;;                        st3  kid3  msw3  sig3
;;; ? (cert-export (list (nth 0 *keyring*) (nth 1 *keyring*)))
;;; ((PUBLIC-KEY-PACKET OLD-HEADER-3 VERSION-4 ...))
;;;

(defun gpg5-export (keylist)

  ;; Make sure the input list is okay.
  (if (not (and
	    (listp keylist)
	    (= 2 (length keylist))
	    (rsa-LS-keyp (nth 0 keylist))
	    (rsa-LC-keyp (nth 1 keylist))))
      (error "keylist must be a list of two local keys"))

  ;; Set up the target and the two sources.
  (let ((gpg5-cert) (rsa-LS-key) (rsa-LC-key))
    (setf gpg5-cert (copy-list gpg5-cert-form))
    (setf rsa-LS-key (copy-list (nth 0 keylist)))
    (setf rsa-LC-key (copy-list (nth 1 keylist)))

    ;; Fill PUBLIC-KEY-PACKET pub timestamp ktp with signet key-time.
    (setf (nth 3 (nth 0 gpg5-cert))
	  (nth 2 rsa-LS-key))

    ;; Fill PUBLIC-KEY-PACKET vn with signet modulus,
    ;; where the modulus is the product of prime-p and prime-q.
    (setf (nth 5 (nth 0 gpg5-cert))
	  (* (nth 5 rsa-LS-key) (nth 6 rsa-LS-key)))

    ;; Fill PUBLIC-KEY-PACKET ve with signet encryptor,
    ;; which is the modular inverse of the decryptor (mod lambda),
    ;; where lambda is the carmichael function of prime-p and prime-q.
    (setf (nth 6 (nth 0 gpg5-cert))
	  (mod-inverse (carmichael (nth 5 rsa-LS-key) (nth 6 rsa-LS-key))
		       (nth 4 rsa-LS-key)))

    ;; Fill USER-ID-PACKET ui with signet user-id.
    (setf (nth 2 (nth 1 gpg5-cert)) (nth 3 rsa-LS-key))

    ;; Fill 1st SIGNATURE-PACKET st1.
    (setf (nth 2 (nth 0 (nth 6 (nth 2 gpg5-cert)))) (epoch1970-timestamp))

    ;; Fill 1st SIGNATURE-PACKET ISSUER kid1 with signet key-hash.
    (setf (nth 2 (nth 0 (nth 7 (nth 2 gpg5-cert)))) (nth 1 rsa-LS-key))

    ;; Calculate 1st SIGNATURE-PACKET msw1.
    (setf (nth 8 (nth 2 gpg5-cert)) (gpg5-hash-msw-1 gpg5-cert))

    ;; Calculate 1st SIGNATURE-PACKET sig1 using the signet decryptor
    ;; and the signet modulus, which is the product of prime-p and prime-q.
    (setf (nth 9 (nth 2 gpg5-cert))
	  (modex (pkcs-sign-base 
		  (gpg5-hash-1 gpg5-cert)
		  (nbytes (* (nth 5 rsa-LS-key) (nth 6 rsa-LS-key)))
		  'SHA-1)
		 (nth 4 rsa-LS-key)
		 (* (nth 5 rsa-LS-key) (nth 6 rsa-LS-key))))


    ;; Fill PUBLIC-SUBKEY-PACKET sub timestamp kts with cipher key-time.
    (setf (nth 3 (nth 3 gpg5-cert)) (nth 2 rsa-LC-key))

    ;; Fill PUBLIC-SUBKEY-PACKET cn with the cipher modulus,
    ;; which is the product of prime-p and prime-q.
    (setf (nth 5 (nth 3 gpg5-cert))
	  (* (nth 5 rsa-LC-key) (nth 6 rsa-LC-key)))

    ;; Fill PUBLIC-SUBKEY-PACKET ce with cipher encryptor,
    ;; which is the modular inverse of the decryptor (mod lambda),
    ;; where lambda is the Carmichael function of prime-p and prime-q.
    (setf (nth 6 (nth 3 gpg5-cert))
	  (mod-inverse (carmichael (nth 5 rsa-LC-key) (nth 6 rsa-LC-key))
		       (nth 4 rsa-LC-key)))

    ;; Fill 2nd SIGNATURE-PACKET inner timestamp st3.
    (setf (nth 2 (nth 0 (nth 6 (nth 1 (nth 7 (nth 4 gpg5-cert))))))
	  (epoch1970-timestamp))

    ;; Fill 2nd SIGNATURE-PACKET inner ISSUER kid3 with cipher key-hash.
    (setf (nth 2 (nth 0 (nth 7 (nth 1 (nth 7 (nth 4 gpg5-cert))))))
	  (nth 1 rsa-LC-key))

    ;; Fill 2nd SIGNATURE-PACKET inner msw3.
    (setf (nth 8 (nth 1 (nth 7 (nth 4 gpg5-cert))))
	  (gpg5-hash-msw-3 gpg5-cert))

    ;; Fill 2nd SIGNATURE-PACKET inner sig3.
    (setf (nth 9 (nth 1 (nth 7 (nth 4 gpg5-cert))))
	  (modex
	   (pkcs-sign-base
	    (gpg5-hash-3 gpg5-cert)
	    (nbytes (* (nth 5 rsa-LC-key) (nth 6 rsa-LC-key)))
	    'SHA-1)
	   (nth 4 rsa-LC-key)
	   (* (nth 5 rsa-LC-key) (nth 6 rsa-LC-key))))

    ;; Fill 2nd SIGNATURE-PACKET outer timestamp st2.
    (setf (nth 2 (nth 0 (nth 6 (nth 4 gpg5-cert))))
	  (epoch1970-timestamp))

    ;; Fill 2nd SIGNATURE-PACKET outer ISSUER kid2 with signet key-hash.
    (setf (nth 2 (nth 0 (nth 7 (nth 4 gpg5-cert))))
	  (nth 1 rsa-LS-key))

    ;; Fill 2nd SIGNATURE-PACKET outer msw2.
    (setf (nth 8 (nth 4 gpg5-cert))
	  (gpg5-hash-msw-2 gpg5-cert))

    ;; Fill 2nd SIGNATURE-PACKET outer sig2.
    (setf (nth 9 (nth 4 gpg5-cert))
	  (modex
	   (pkcs-sign-base 
	    (gpg5-hash-2 gpg5-cert)
	    (nbytes (* (nth 5 rsa-LS-key) (nth 6 rsa-LS-key)))
	    'SHA-1)
	   (nth 4 rsa-LS-key)
	   (* (nth 5 rsa-LS-key) (nth 6 rsa-LS-key))))

    ;; End gpg5-export.
    gpg5-cert
    ))


;;;
;;; cert-export
;;; translates a local keyfile into a gpg5 certificate file.
;;;

(defun cert-export (ifile ofile)
  (if (not (stringp ifile)) (error "ifile must be a string"))
  (if (not (stringp ofile)) (error "ofile must be a string"))
  (let ((keylist) (gpg5-cert))
    (setf keylist (getlist ifile))
    (setf gpg5-cert (gpg5-export keylist))
    (putfile ofile (build-message gpg5-cert))))


;;;
;;; gpg5-import
;;; translates a gpg5 certificate to a local key list.
;;; Input must be a list that contains a gpg5 certificate message.
;;; Output is a list of two remote keys, RSA-RS and RSA-RC.
;;;

(defun gpg5-import (gpg5-cert)

  ;; Make certain that the certificate is valid and verified.
  (if (not (and (gpg5-cert-p gpg5-cert) (gpg5-verified-p gpg5-cert)))
      (return-from gpg5-import nil))

  (list 
   ;; remote signet key
   (list 'RSA-RS                         ; key-type
	 (pgp-key-id (nth 0 gpg5-cert))  ; key-hash
	 (nth 3 (nth 0 gpg5-cert))       ; key-time
	 (nth 2 (nth 1 gpg5-cert))       ; user-id
	 (nth 5 (nth 0 gpg5-cert))       ; modulus
	 (nth 6 (nth 0 gpg5-cert)))      ; encryptor

   ;; remote cipher key
   (list 'RSA-RC                         ; key-type
	 (pgp-key-id (nth 3 gpg5-cert))  ; key-hash
	 (nth 3 (nth 3 gpg5-cert))       ; key-time
	 (nth 2 (nth 1 gpg5-cert))       ; user-id
	 (nth 5 (nth 3 gpg5-cert))       ; modulus
	 (nth 6 (nth 3 gpg5-cert)))))    ; encryptor


;;;
;;; cert-import
;;; translates a gpg5 certificate file into a remote keyfile.
;;; Input is two strings. 
;;; The 1st string specifies the path and filename of a gpg5 certificate file.
;;; the 2nd string specifies the path and filename for the local keyfile.
;;;

(defun cert-import (ifile ofile)

  (if (not (stringp ifile)) (error "ifile must be a string"))
  (if (not (stringp ofile)) (error "ofile must be a string"))
  (let ((gpg5-cert) (keylist) (ks nil) (kc nil) (bl nil))
    (setf gpg5-cert (parse-message (getfile ifile)))
    (setf keylist (gpg5-import gpg5-cert))
    (setf ks (nth 0 keylist))
    (setf kc (nth 1 keylist))

    ;; Append a formatted header to the byte-list bl.
    (setf bl (append bl (split-str 
      (format nil ";; ~A~%~%" ofile))))

    ;; Append formatted ks values to the byte-list bl.
    (setf bl (append bl (split-str
      (format nil "((~A  \"~A\"  \"~A\"  \"~A\"~%"
        (nth 0 ks) (nth 1 ks) (nth 2 ks) (nth 3 ks)))))
    (setf bl (append bl (split-str
      (format nil "  ~A~%" (nth 4 ks)))))
    (setf bl (append bl (split-str
      (format nil "  ~A)~%~%" (nth 5 ks)))))

    ;; Append formatted kc values to the byte-list bl.
    (setf bl (append bl (split-str
      (format nil " (~A  \"~A\"  \"~A\"  \"~A\"~%"
        (nth 0 kc) (nth 1 kc) (nth 2 kc) (nth 3 kc)))))
    (setf bl (append bl (split-str
      (format nil "  ~A~%" (nth 4 kc)))))
    (setf bl (append bl (split-str
      (format nil "  ~A))~%~%" (nth 5 kc)))))

    ;; Finally, write the byte-list bl to the file.
    (putfile ofile bl)))


;;;
;;; cert-okayp
;;; tests the cert-export and cert-import functions.
;;;

(defun cert-okayp ()
  (let ((local-list nil)      ; list of Mike's local keys
	(remote-list nil)     ; list of Mike's remote keys
	(rsa-LS-key nil)      ; Mike's local signet key
	(rsa-LC-key nil)      ; Mike's local cipher key
	(rsa-RS-key nil)      ; Mike's remote signet key
	(rsa-RC-key nil))     ; Mike's remote cipher key

    ;; Export Mike's keys into an OpenPGP certificate.
    ;; Import Mike's keys from an OpenPGP certificate.
    (cert-export "../Test/Mike.loc" "../Test/Mike.pgp")
    (cert-import "../Test/Mike.pgp" "../Test/Mike.rem")

    ;; Get Mike's local list and remote list.
    (setf local-list (getlist "../Test/Mike.loc"))
    (setf remote-list (getlist "../Test/Mike.rem"))

    ;; Delete the temporary files.
    (delete-file "../Test/Mike.pgp")
    (delete-file "../Test/Mike.rem")

    ;; Verify that...
    (and 

     ;; local-list is a list of two lists,
     ;; the 1st list is a valid RSA-LS,
     ;; the 2nd list is a valid RSA-LC,
     (listp local-list)
     (= 2 (length local-list))
     (rsa-LS-keyp (setf rsa-LS-key (nth 0 local-list)))
     (rsa-LC-keyp (setf rsa-LC-key (nth 1 local-list)))
 
     ;; remote-list is a list of two lists,
     ;; the 1st list is a valid RSA-RS,
     ;; the 2nd list is a valid RSA-RC,
     (listp remote-list)
     (= 2 (length remote-list))
     (rsa-RS-keyp (setf rsa-RS-key (nth 0 remote-list)))
     (rsa-RC-keyp (setf rsa-RC-key (nth 1 remote-list)))
 
     ;; the key-hash in RSA-RS is the same as the key-hash in RSA-LS,
     ;; the key-hash in RSA-RC is the same as the key-hash in RSA-LC,
     (equal (nth 1 rsa-RS-key) (nth 1 rsa-LS-key))
     (equal (nth 1 rsa-RC-key) (nth 1 rsa-LC-key))

     ;; the modulus in RSA-RS equals (* p q) in RSA-LS,
     ;; the modulus in RSA-RC equals (* p q) in RSA-LC,
     (= (nth 4 rsa-RS-key) (* (nth 5 rsa-LS-key)
			      (nth 6 rsa-LS-key)))
     (= (nth 4 rsa-RC-key) (* (nth 5 rsa-LC-key)
			      (nth 6 rsa-LC-key)))

     ;; the product of encryptor e in RSA-RS and decryptor d in RSA-LS is 1,
     ;; the product of encryptor e in RSA-RC and decryptor d in RSA-LC is 1,
     (= 1 (otimes (nth 5 rsa-RS-key)
		  (nth 4 rsa-LS-key)
		  (carmichael (nth 5 rsa-LS-key)
			      (nth 6 rsa-LS-key))))
     (= 1 (otimes (nth 5 rsa-RC-key)
		  (nth 4 rsa-LC-key)
		  (carmichael (nth 5 rsa-LC-key)
			      (nth 6 rsa-LC-key))))

     ;; End cert-okayp.
     )))


