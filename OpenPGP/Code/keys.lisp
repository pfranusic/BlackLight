;;;; BlackLight/OpenPGP/keys.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; Lisp code for BlackLight OpenPGP keys.
;;;;
;;;; Def: a "key" is a list that contains cryptographic integers.
;;;; *keyring* is a list of keys.
;;;; rsa-LS-keyp returns T iff a list is an RSA Local Signet key.
;;;; rsa-LC-keyp returns T iff a list is an RSA Local Cipher key.
;;;; rsa-RS-keyp returns T iff a list is an RSA Remote Signet key.
;;;; rsa-RC-keyp returns T iff a list is an RSA Remote Cipher key.
;;;; make-key generates either an RSA-LS key or an RSA-LC key.
;;;; create-local-keyfile writes two local keys into a keyfile.
;;;; load-keyring loads *keyring* with keys from various keyfiles.
;;;; keys-okayp returns T if the "keys" module is okay.
;;;;


;;;
;;; *keyring*
;;; The keyring is a simply a list of keys.
;;; Each key in the keyring is itself a list.
;;; There are four types of BlackLight RSA keys:
;;; RSA-LS is a "Local Signet" key and is used to sign transmitted messages.
;;; RSA-LC is a "Local Cipher" key and is used to decrypt received messages.
;;; RSA-RS is a "Remote Signet" key and is used to verify received messages.
;;; RSA-RC is a "Remote Cipher" key is used to encrypt transmitted messages.
;;; Here we initialize *keyring* to the empty list.
;;; *keyring* can be loaded with the "load-keyring" command.
;;;
;;; (defparameter *keyring* nil)       
;;;


;;;
;;; RSA Local Signet key format:
;;;
;;;  0     key-type      RSA-LS
;;;  1     key-hash      "B49475B3CE22E2E8"
;;;  2     key-time      "2011-Jun-06 02:03:10 UTC"
;;;  3     user-id       "Zeta"
;;;  4     decryptor     101212204575912833841983183689481822564955231871...
;;;  5     prime-p       134018372838869002527903...
;;;  6     prime-q       134040911966554158119122...
;;;

;;;
;;; rsa-LS-keyp
;;; returns T iff k is an "RSA Local Signet" key.
;;; ? (rsa-LS-keyp (nth 0 (getlist "../Test/Zeta.loc")))
;;;

(defun rsa-LS-keyp (k)
  (and (listp k)                    ; list
       (= 7 (length k))
       (symbolp (nth 0 k))          ; key-type
       (eql 'RSA-LS (nth 0 k))
       (hex-stringp (nth 1 k))      ; key-hash
       (= 16 (length (nth 1 k)))
       (time-stringp (nth 2 k))     ; key-time
       (stringp (nth 3 k))          ; user-id
       (integerp (nth 4 k))         ; decryptor
       (> (nth 4 k) (expt 2 500))
       (integerp (nth 5 k))         ; prime-p
       (> (nth 5 k) (expt 2 250))
       (integerp (nth 6 k))         ; prime-q
       (> (nth 6 k) (expt 2 250))
       ))


;;;
;;; "RSA Local Cipher" key format:
;;;
;;;  0     key-type      RSA-LC
;;;  1     key-hash      "E668E1DF1AACCA93"
;;;  2     key-time      "2011-Jun-27 21:37:14 UTC"
;;;  3     user-id       "Zane"
;;;  4     decryptor     508116420496440350422565624528475645312943597272...
;;;  5     prime-p       134004832859910460950742...
;;;  6     prime-q       134043380404990986795066...
;;;

;;;
;;; rsa-LC-keyp
;;; returns T iff k is an "RSA Local Cipher" key.
;;; ? (rsa-LC-keyp (nth 1 (getlist "../Test/Zane.loc")))
;;;

(defun rsa-LC-keyp (k)
  (and (listp k)                    ; list
       (= 7 (length k))
       (symbolp (nth 0 k))          ; key-type
       (eql 'RSA-LC (nth 0 k))
       (hex-stringp (nth 1 k))      ; key-hash
       (= 16 (length (nth 1 k)))
       (time-stringp (nth 2 k))     ; key-time
       (stringp (nth 3 k))          ; user-id
       (integerp (nth 4 k))         ; decryptor
       (> (nth 4 k) (expt 2 500))
       (integerp (nth 5 k))         ; prime-p
       (> (nth 5 k) (expt 2 250))
       (integerp (nth 6 k))         ; prime-q
       (> (nth 6 k) (expt 2 250))
       ))


;;;
;;; "RSA Remote Signet" key format:
;;;
;;;  0     key-type      RSA-RS
;;;  1     key-hash      "B49475B3CE22E2E8"
;;;  2     key-time      "2011-Jun-06 02:03:10 UTC"
;;;  3     user-id       "Zeta"
;;;  4     modulus       179639449155956728402691106069912172658276080543...
;;;  5     encryptor     871849710382310675948430611783183976392129855473...
;;;

;;;
;;; rsa-RS-keyp
;;; returns T iff k is an "RSA Remote Signet" key.
;;; ? (rsa-RS-keyp (nth 0 (getlist "../Test/Genny.rem")))
;;; T
;;;

(defun rsa-RS-keyp (k)
  (and (listp k)                    ; list
       (= 6 (length k))
       (symbolp (nth 0 k))          ; nth 0
       (eql 'RSA-RS (nth 0 k))
       (hex-stringp (nth 1 k))      ; nth 1
       (= 16 (length (nth 1 k)))
       (time-stringp (nth 2 k))     ; nth 2
       (stringp (nth 3 k))          ; nth 3
       (integerp (nth 4 k))         ; nth 4
       (> (nth 4 k) (expt 2 500))
       (integerp (nth 5 k))         ; nth 5
       (> (nth 5 k) 65536)
       ))


;;;
;;; "RSA Remote Cipher" key format:
;;;
;;;  0     key-type      RSA-RC
;;;  1     key-hash      "E668E1DF1AACCA93"
;;;  2     key-time      "2011-Jun-27 21:37:14 UTC"
;;;  3     user-id       "Zane"
;;;  4     modulus       179624607871482141784386910009764728558111198170...
;;;  5     encryptor     724901174591902003438063530454712308804165066546...
;;;

;;;
;;; rsa-RC-keyp
;;; returns T iff k is an "RSA Remote Cipher" key.
;;; ? (rsa-RC-keyp (nth 1 (getlist "../Test/Genny.rem")))
;;; T
;;;

(defun rsa-RC-keyp (k)
  (and (listp k)                    ; list
       (= 6 (length k))
       (symbolp (nth 0 k))          ; nth 0
       (eql 'RSA-RC (nth 0 k))
       (hex-stringp (nth 1 k))      ; nth 1
       (= 16 (length (nth 1 k)))
       (time-stringp (nth 2 k))     ; nth 2
       (stringp (nth 3 k))          ; nth 3
       (integerp (nth 4 k))         ; nth 4
       (> (nth 4 k) (expt 2 500))
       (integerp (nth 5 k))         ; nth 5
       (> (nth 5 k) 65536)
       ))


;;;
;;; make-key
;;; generates an RSA-LS or RSA-LC with 
;;; a random modulus in [2^{nz-0.49}, 2^{nz-0.99}].
;;; Input is the key symbol (ks), the User ID string (ui), 
;;; and the modulus-size float (nz).
;;; ? (make-key 'RSA-LS "Bob" 299.5)
;;;

(defun make-key (ks ui nz)

  ;; Check the three arguments.
  (if (not (symbolp ks))
      (error "ks must be a symbol"))
  (if (not (or (eql ks 'RSA-LS) (eql ks 'RSA-LC)))
      (error "ks value is invalid"))
  (if (not (and (stringp ui) (/= 0 (length ui))))
      (error "ui must be a non-empty string"))
  (if (not (and (floatp nz) (> nz 299.0)))
      (error "nz must be a float greater than 299.0"))

  ;; Define the local variables.
  (let ((pq-list) (p) (q) (lambda)
	(d) (e) (n) (kt) (v) (ki))

    ;; Get a pair of primes p and q with all the right stuff.
    (setf pq-list (prime-pair nz))
    (setf p (nth 0 pq-list))
    (setf q (nth 1 pq-list))
    (setf lambda (carmichael p q))

    ;; Compute the data for the list.
    (setf d (random-decryptor lambda))
    (setf e (mod-inverse lambda d))
    (setf n (* p q))
    (setf kt (epoch1970-timestamp))
    (setf v (v4-fingerprint (list 'NIL 'NIL 'VERSION-4 kt 'NIL n e)))
    (setf ki (format nil "~16,'0X" (mod v (expt 2 64))))

    ;; Output the list.
    (case ks	  
	  (RSA-LS  (list 'RSA-LS ki kt ui d p q))
	  (RSA-LC  (list 'RSA-LC ki kt ui d p q)))
    ))


;;;
;;; create-local-keyfile
;;; generates RSA-LS and RSA-LC keys and copies them to a file.
;;; Input is the pathname string pn, the User-ID string ui, 
;;; and the modulus float nz. Output is the file length.
;;; ? (create-local-keyfile "../Test" "Mike" 1023.995)
;;;

(defun create-local-keyfile (pn ui nz)

  ;; Check the pathname string pn.
  (if (not (stringp pn)) (error "pn must be a string"))
  (if (= 0 (length pn)) (error "pn is an empty string"))

  ;; Check the user-ID string ui.
  (if (not (stringp ui)) (error "ui must be a string"))
  (if (= 0 (length ui)) (error "ui is an empty string"))

  ;; Check the modulus float nz.
  (if (not (floatp nz)) (error "nz must be an float"))
  (if (not (> nz 299.0)) (error "nz is too small"))
  (if (not (< nz 8192.0)) (error "nz is too large"))

  ;; Define local variables:
  ;; signet-key ks is a list with 10 elements.
  ;; cipher-key kc is a list with 10 elements.
  ;; byte-list bl is a list of bytes destined for putfile.
  (let ((ks nil) (kc nil) (bl nil))

    ;; Generate the signet-key ks and cipher-key kc.
    (setf ks (make-key 'RSA-LS ui nz))
    (setf kc (make-key 'RSA-LC ui nz))

    ;; Append a formatted header to the byte-list bl.
    (setf bl (append bl (split-str 
      (format nil ";; ~A.loc~%~%" ui))))

    ;; Append formatted ks values to the byte-list bl.
    (setf bl (append bl (split-str
      (format nil "((~A  \"~A\"  \"~A\"  \"~A\"~%"
        (nth 0 ks) (nth 1 ks) (nth 2 ks) (nth 3 ks)))))
    (setf bl (append bl (split-str
      (format nil "  ~A~%" (nth 4 ks)))))
    (setf bl (append bl (split-str
      (format nil "  ~A~%" (nth 5 ks)))))
    (setf bl (append bl (split-str
      (format nil "  ~A)~%~%" (nth 6 ks)))))

    ;; Append formatted kc values to the byte-list bl.
    (setf bl (append bl (split-str
      (format nil " (~A  \"~A\"  \"~A\"  \"~A\"~%"
        (nth 0 kc) (nth 1 kc) (nth 2 kc) (nth 3 kc)))))
    (setf bl (append bl (split-str
      (format nil "  ~A~%" (nth 4 kc)))))
    (setf bl (append bl (split-str
      (format nil "  ~A~%" (nth 5 kc)))))
    (setf bl (append bl (split-str
      (format nil "  ~A))~%~%" (nth 6 kc)))))

    ;; Finally, write the byte-list bl to the file.
    (putfile (format nil "~A/~A.loc" pn ui) bl)))


;;;
;;; The following functions are used to access data in the keyring.
;;; They use either a key-hash or a user-id as the argument.
;;;


;;;
;;; key-owner
;;; returns a user-id, given a key-hash.
;;; ? (key-owner "B49475B3CE22E2E8")
;;; "Zeta"
;;;

(defun key-owner (key-hash)
  (if (not (and (hex-stringp key-hash) (= 16 (length key-hash))))
      (error "key-hash must be a hex-string with 16 digits"))
  (dotimes (i (length *keyring*))
    (if (equal key-hash (nth 1 (nth i *keyring*)))
	(return-from key-owner
		     (nth 3 (nth i *keyring*)))))
  (error "key-hash ~A does not exist" key-hash))


;;;
;;; local-decryptor
;;; returns an RSA-LS or RSA-LC decryptor, given a key-hash.
;;; ? (local-decryptor "B49475B3CE22E2E8")
;;; 101212204575912833841983183689481822564955231871...
;;;

(defun local-decryptor (key-hash)
  (if (not (and (hex-stringp key-hash) (= 16 (length key-hash))))
      (error "key-hash must be a hex-string with 16 digits"))
  (dotimes (i (length *keyring*))
    (if (and (equal key-hash (nth 1 (nth i *keyring*)))
	     (or (equal 'RSA-LS (nth 0 (nth i *keyring*)))
		 (equal 'RSA-LC (nth 0 (nth i *keyring*)))))
	(return-from local-decryptor
		     (nth 4 (nth i *keyring*)))))
  (error "key-hash ~A does not exist" key-hash))


;;;
;;; local-modulus
;;; returns an RSA-LS or RSA-LC modulus, given a key-hash.
;;; The modulus must be computed from prime-p and prime-q.
;;; ? (local-modulus "B49475B3CE22E2E8")
;;; 179639449155956728402691106069912172658276080543...
;;;

(defun local-modulus (key-hash)
  (if (not (and (hex-stringp key-hash) (= 16 (length key-hash))))
      (error "key-hash must be a hex-string with 16 digits"))
  (dotimes (i (length *keyring*))
    (if (and (equal key-hash (nth 1 (nth i *keyring*)))
	     (or (equal 'RSA-LS (nth 0 (nth i *keyring*)))
		 (equal 'RSA-LC (nth 0 (nth i *keyring*)))))
	(return-from local-modulus 
		     (* (nth 5 (nth i *keyring*))
			(nth 6 (nth i *keyring*))))))
  (error "key-hash ~A does not exist" key-hash))


;;;
;;; remote-encryptor
;;; returns an RSA-RS or RSA-RC encryptor, given a key-hash.
;;; ? (remote-encryptor "B49475B3CE22E2E8")
;;; 871849710382310675948430611783183976392129855473...
;;;

(defun remote-encryptor (key-hash)
  (if (not (and (hex-stringp key-hash) (= 16 (length key-hash))))
      (error "key-hash must be a hex-string with 16 digits"))
  (dotimes (i (length *keyring*))
    (if (and (equal key-hash (nth 1 (nth i *keyring*)))
	     (or (equal 'RSA-RS (nth 0 (nth i *keyring*)))
		 (equal 'RSA-RC (nth 0 (nth i *keyring*)))))
	(return-from remote-encryptor
		     (nth 5 (nth i *keyring*)))))
  (error "key-hash ~A does not exist" key-hash))


;;;
;;; remote-modulus
;;; returns an RSA-RS or RSA-RC modulus, given a key-hash.
;;; ? (remote-modulus "B49475B3CE22E2E8")
;;; 179639449155956728402691106069912172658276080543...
;;;

(defun remote-modulus (key-hash)
  (if (not (and (hex-stringp key-hash) (= 16 (length key-hash))))
      (error "key-hash must be a hex-string with 16 digits"))
  (dotimes (i (length *keyring*))
    (if (and (equal key-hash (nth 1 (nth i *keyring*)))
	     (or (equal 'RSA-RS (nth 0 (nth i *keyring*)))
		 (equal 'RSA-RC (nth 0 (nth i *keyring*)))))
	(return-from remote-modulus
		     (nth 4 (nth i *keyring*)))))
  (error "key-hash ~A does not exist" key-hash))


;;;
;;; local-signet-hash
;;; returns the key-hash for an RSA-LS, given a user-id.
;;; ? (local-signet-hash "Zeta")
;;; "B49475B3CE22E2E8"
;;;

(defun local-signet-hash (user-id)
  (if (not (stringp user-id))
      (error "user-id must be a string"))
  (dotimes (i (length *keyring*))
    (if (and (equal user-id (nth 3 (nth i *keyring*)))
	     (equal 'RSA-LS (nth 0 (nth i *keyring*))))
	(return-from local-signet-hash
		     (nth 1 (nth i *keyring*)))))
  (error "~A doesn't have an RSA-RC key" user-id))


;;;
;;; remote-cipher-hash
;;; returns the key-hash for an RSA-RC, given a user-id.
;;; ? (remote-cipher-hash "Zane")
;;; "E668E1DF1AACCA93"
;;;

(defun remote-cipher-hash (user-id)
  (if (not (stringp user-id))
      (error "user-id must be a string"))
  (dotimes (i (length *keyring*))
    (if (and (equal user-id (nth 3 (nth i *keyring*)))
	     (equal 'RSA-RC (nth 0 (nth i *keyring*))))
	(return-from remote-cipher-hash
		     (nth 1 (nth i *keyring*)))))
  (error "~A doesn't have an RSA-RC key" user-id))


;;;
;;; load-keyring
;;; returns the number of keys loaded into the keyring.
;;; Given the pathname of a directory, it checks the validity
;;; of each keyfile named in the LOAD-THESE file.
;;; If and only if each of these keyfiles is valid,
;;; it then loads each key onto the keyring.
;;; Ex: (load-keyring "../Test")
;;;

(defun load-keyring (pathname)
  (if (not (stringp pathname))
      (error "pathname must be a string"))
  (let ((keyfiles nil) (kf nil))

    ;; Check each key named in keyfiles.
    (setf keyfiles (getlist (format nil "~A/LOAD-THESE" pathname)))
    (dotimes (i (length keyfiles))
      (setf kf (getlist (format nil "~A/~A" pathname (nth i keyfiles))))
      (if (not (and (= 2 (length kf))
		    (listp (nth 0 kf))
		    (listp (nth 1 kf))))
	  (error "~A is not a valid keyfile" (nth i keyfiles)))
      (if (not (or (and (rsa-LS-keyp (nth 0 kf))
			(rsa-LC-keyp (nth 1 kf)))
		   (and (rsa-RS-keyp (nth 0 kf))
			(rsa-RC-keyp (nth 1 kf)))))
	  (error "~A contains an invalid key" (nth i keyfiles))))

    ;; Load each key named in keyfiles.
    (setf *keyring* nil)
    (dotimes (i (length keyfiles))
      (setf *keyring* (append *keyring* 
	(getlist (format nil "~A/~A" pathname (nth i keyfiles)))))))

  ;; Return the number of keys now in the keyring.
  (length *keyring*))


;;;
;;; keys-okayp
;;; tests most of the functions in this module.
;;; First, it creates some new keys in the Test directory,
;;; loads a test keyring, and runs some tests. When done,
;;; it loads a test keyring from the Test directory.
;;;

(defun keys-okayp ()
  (load-keyring "../Test")
  T)


