;;;; BlackLight/OpenPGP/system.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; system-make compiles and loads newly-edited files.
;;;; system-load loads all DFSL files.
;;;; system-test verifies that everything works.
;;;;


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
    ("comm-form" comm-form-okayp)
    ("comm" comm-okayp)
    ))


;;;
;;; dfsl-exists-newer-p
;;; returns T iff the DFSL file exists
;;; and its file-write-date is more recent than 
;;; the file-write date of the corresponding LISP file.
;;;

(defun dfsl-exists-newer-p (module-name)
  (and (not (equal nil (probe-file (format nil "~A.dfsl" module-name))))
       (> (file-write-date (format nil "~A.dfsl" module-name))
	  (file-write-date (format nil "~A.lisp" module-name)))))


;;; 
;;; system-load
;;; Load all DFSL files:
;;; Check the existence and write-time of each DFSL file listed in the modules list.
;;; If the DFSL file exists and its write-time is newer than the write-time of 
;;; the corresponding LISP file, then load the DFSL file;  otherwise, 
;;; generate a diagnostic message ("Need to run system-make") and exit.
;;; Return DONE.
;;; 

(defun system-load ()
  (let ((module-name))
    (dotimes (i (length modules))
      (setf module-name (nth 0 (nth i modules)))
      (if (not (dfsl-exists-newer-p module-name))
	  (progn
	    (format t "Need to run system-make")
	    (return-from system-load 'DONE)))
      (load (format nil "~A" module-name))))
  (format t "System loaded")
  'DONE)


;;; 
;;; system-make
;;; Compile and load newly-edited files:
;;; Check the existence of each LISP file listed in the modules list.
;;; If the LISP file does not exist, generate a diagnostic message 
;;; ("foobar.lisp does not exist") and exit.
;;; Check the existence and write-time of each DFSL file listed in the modules list.
;;; If the DFSL file exists and its write-time is newer than the write-time of the
;;; corresponding LISP file, then load the DFSL file;  otherwise, compile the DFSL file 
;;; with a message (compile-file "foobar") and then immediately load it.
;;; Print "System is up to date" if no compiles were needed.
;;; 

(defun system-make ()
  (let ((compile-needed nil) (module-name))
    (dotimes (i (length modules))
      (setf module-name (nth 0 (nth i modules)))
      (if (equal nil (probe-file (format nil "~A.lisp" module-name)))
	  (progn
	    (format t "~A.lisp does not exist" module-name)
	    (return-from system-make 'DONE)))
      (if (not (dfsl-exists-newer-p module-name))
	  (progn
	    (setf compile-needed T)
	    (format t "(compile-file \"~A\")~%" module-name)
	    (compile-file (format nil "~A" module-name))
	    (format t "(load \"~A\")~%" module-name)
	    (load (format nil "~A" module-name)))))
    (if (not compile-needed)
	(format t "System is up to date")))
  'DONE)


;;; 
;;; system-test
;;; Verify that everything works:
;;; Invoke each test listed in the modules list.
;;; For each test, print a message with the test result ("Testing foobar... okay").
;;; Return DONE.
;;; 

(defun system-test ()
  (let ((module-name) (test-name))
    (dotimes (i (length modules))
      (setf module-name (nth 0 (nth i modules)))
      (setf test-name (nth 1 (nth i modules)))
      (format t "Testing ~A module... " module-name)
      (if (eval `(,test-name))
	  (format t "okay~%") (format t "FAILED~%"))))
  'DONE)


;;;
;;; Load the system now!
;;;

;;;; TEMP ;;;; (system-load)


