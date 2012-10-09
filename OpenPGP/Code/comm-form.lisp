;;;; BlackLight/OpenPGP/comm-form.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; comm-form module overview:
;;;; A standard GnuPG communique consists of
;;;; a two-packet OpenPGP message (comm-form-1) that encapsulates
;;;; a one-packet OpenPGP message (comm-form-2) that encapsulates
;;;; a three-packet OpenPGP message (comm-form-3).
;;;; The idea is to read or write the custom values in the "holes" which
;;;; are marked with a ";####" followed by an access expression.
;;;;


;;;
;;; comm-form-1
;;; This is the form for the two-packet OpenPGP message.
;;; It is part of the larger, standard GnuPG communique.
;;; (nth 3 (nth 0 m1)) is the key-hash of the receiver's remote cipher key.
;;; (nth 5 (nth 0 m1)) is the padded AES-128 session key encrypted using
;;; the receiver's remote cipher key.
;;; (nth 2 (nth 1 m1)) is the ZLIB deflated data encrypted using the 
;;; AES-128 session key in CFB mode.
;;;

(defconstant comm-form-1
  '((PKE-SESSION-KEY-PACKET
     OLD-HEADER-2
     VERSION-3
     "FFFFFFFFFFFFFFFF"                                  ;#### (nth 3 (nth 0 m1)) ; kid1
     RSA-ENCR-SIGN
     99999999999999999999999999999999999999999999999)    ;#### (nth 5 (nth 0 m1)) ; esk
    (SYM-ENCR-DATA-PACKET
     OLD-HEADER-5
     (255 255 255 255 255 255 255 255 255 255 255 255    ;#### (nth 2 (nth 1 m1))
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 ))))


;;;
;;; comm-form-2
;;; This is the form for the one-packet OpenPGP message.
;;; It is part of the larger, standard GnuPG communique.
;;; (nth 3 (nth 0 m2)) is the ZLIB deflated data.
;;;

(defconstant comm-form-2
  '((COMPRESSED-DATA-PACKET
     OLD-HEADER-I
     ZLIB
     (255 255 255 255 255 255 255 255 255 255 255 255    ;#### (nth 3 (nth 0 m2))
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 ))))



;;;
;;; comm-form-3
;;; This is the form for the three-packet OpenPGP message.
;;; It is part of the larger, standard GnuPG communique.
;;; (nth 6 (nth 0 m3)) is the key-hash of the sender's signet key.
;;; (nth 3 (nth 1 m3)) is a filename string.
;;; (nth 4 (nth 1 m3)) is an epoch1970 timestamp string.
;;; (nth 5 (nth 1 m3)) is the plaintext binary data.
;;; (nth 2 (nth 0 (nth 6 (nth 2 m3)))) is an epoch1970 timestamp string.
;;; (nth 2 (nth 0 (nth 7 (nth 2 m3)))) is the key-hash of the sender's signet key.
;;; (nth 8 (nth 2 m3)) is the MSW of the sha256 hash product.
;;; (nth 9 (nth 2 m3)) is the signature using the sender's signet key.
;;;

(defconstant comm-form-3
  '((ONE-PASS-SIGNATURE-PACKET
     OLD-HEADER-2 
     VERSION-3
     BINARY-SIGNATURE
     SHA-256
     RSA-ENCR-SIGN
     "FFFFFFFFFFFFFFFF"                                  ;#### (nth 6 (nth 0 m3)) ; kid2
     1)
    (LITERAL-DATA-PACKET
     OLD-HEADER-5
     BINARY-DATA
     "xxxxx-yyyy.zzz"                                    ;#### (nth 3 (nth 1 m3)) ; fn
     "1970-Jan-01 00:00:00 UTC"                          ;#### (nth 4 (nth 1 m3))
     (255 255 255 255 255 255 255 255 255 255 255 255    ;#### (nth 5 (nth 1 m3))
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255 
      255 255 255 255 255 255 255 255 255 255 255 255))
    (SIGNATURE-PACKET
     OLD-HEADER-2
     VERSION-4
     BINARY-SIGNATURE
     RSA-ENCR-SIGN
     SHA-256
     ((SUBPACKET-A
       SIGNATURE-CREATION-TIME
       "1970-Jan-01 00:00:00 UTC"))        ;#### (nth 2 (nth 0 (nth 6 (nth 2 m3))))
     ((SUBPACKET-A
       ISSUER 
       "FFFFFFFFFFFFFFFF"))                ;#### (nth 2 (nth 0 (nth 7 (nth 2 m3)))) ; kid3
     "FFFF"                                              ;#### (nth 8 (nth 2 m3))
     99999999999999999999999999999999999999999999999))   ;#### (nth 9 (nth 2 m3))   ; sig
  )



;;;
;;; comm-form-okay
;;;

(defun comm-form-okayp ()
  T)

