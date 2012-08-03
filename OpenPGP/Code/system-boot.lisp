;;;; BlackLight/OpenPGP/system-boot.lisp
;;;; Copyright 2012 Peter Franusic
;;;; system-boot compiles and loads the BlackLight OpenPGP DFSL files.
;;;; system-test verifies that everything works.
;;;;


;;;
;;; *keyring*
;;;

(defparameter *keyring* nil)


;;;
;;; OpenPGP system modules
;;;

(defconstant modules
  '(("stdlib" stdlib-okayp)
    ("stdio" stdio-okayp)
    ("modex" modex-okayp)
    ("prime" prime-okayp)
    ("huge" huge-okayp)
    ("time" time-okayp)
    ("radix64" radix64-okayp)
    ("zlib" zlib-okayp)
    ("compr-algs" compr-algs-okayp)
    ("pk-algs" pk-algs-okayp)
    ("sym-algs" sym-algs-okayp)
    ("hash-algs" hash-algs-okayp)
    ("data-types" data-types-okayp)
    ("sig-types" sig-types-okayp)
    ("version-types" version-types-okayp)
    ("subpacket" subpacket-okayp)
    ("packet-C1" packet-C1-okayp)
    ("packet-C2" packet-C2-okayp)
    ("packet-C4" packet-C4-okayp)
    ("packet-C6" packet-C6-okayp)
    ("packet-C8" packet-C8-okayp)
    ("packet-C9" packet-C9-okayp)
    ("packet-CB" packet-CB-okayp)
    ("packet-CD" packet-CD-okayp)
    ("subpacket-02" subpacket-02-okayp)
    ("subpacket-03" subpacket-03-okayp)
    ("subpacket-04" subpacket-04-okayp)
    ("subpacket-05" subpacket-05-okayp)
    ("subpacket-06" subpacket-06-okayp)
    ("subpacket-07" subpacket-07-okayp)
    ("subpacket-09" subpacket-09-okayp)
    ("subpacket-11" subpacket-11-okayp)
    ("subpacket-12" subpacket-12-okayp)
    ("subpacket-16" subpacket-16-okayp)
    ("subpacket-20" subpacket-20-okayp)
    ("subpacket-21" subpacket-21-okayp)
    ("subpacket-22" subpacket-22-okayp)
    ("subpacket-23" subpacket-23-okayp)
    ("subpacket-24" subpacket-24-okayp)
    ("subpacket-25" subpacket-25-okayp)
    ("subpacket-26" subpacket-26-okayp)
    ("subpacket-27" subpacket-27-okayp)
    ("subpacket-28" subpacket-28-okayp)
    ("subpacket-29" subpacket-29-okayp)
    ("subpacket-30" subpacket-30-okayp)
    ("subpacket-31" subpacket-31-okayp)
    ("subpacket-32" subpacket-32-okayp)
    ("header" header-okayp)
    ("packet" packet-okayp)
    ("message" message-okayp)
    ("aes" aes-okayp)
    ("cfb" cfb-okayp)
    ("pkcs" pkcs-okayp)
    ("sha" sha-okayp)
    ("pair" pair-okayp)
    ("keys" keys-okayp)
    ("cert" cert-okayp)
    ("comm" comm-okayp)
    ))


;;;
;;; make-module
;;; compiles a Lisp file into a DFSL file.
;;;

(defun make-module (module-name)
  (if (not (stringp module-name)) (error "module-name must be a string"))
  (format t "Compiling ~A module... ~%" module-name)
  (compile-file (format nil "~A" module-name)))


;;;
;;; load-module
;;; loads a DFSL file into Lisp.
;;;

(defun load-module (module-name)
  (if (not (stringp module-name)) (error "module-name must be a string"))
  (format t "Loading ~A module... ~%" module-name)
  (load (format nil "~A" module-name)))


;;;
;;; test-module
;;; call a test routine for a module.
;;;

(defun test-module (module-name test-name)
  (if (not (stringp module-name)) (error "module-name must be a string"))
  (format t "Testing ~A module... " module-name)
  (if (eval `(,test-name)) (format t "okay~%") (format t "FAILED~%")))


;;;
;;; system-boot
;;; compiles and loads the BlackLight OpenPGP DFSL files.
;;;

(defun system-boot ()
  (dotimes (i (length modules))
    (make-module (nth 0 (nth i modules)))
    (load-module (nth 0 (nth i modules))))
  'DONE)


;;;
;;; system-test
;;; verifies that everything works.
;;;

(defun system-test ()
  (dotimes (i (length modules))
    (test-module (nth 0 (nth i modules))
		 (nth 1 (nth i modules))))
  (setf *keyring* nil)
  'DONE)


