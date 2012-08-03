;;;; BlackLight/OpenPGP/zlib.lisp
;;;; Copyright 2012 Peter Franusic
;;;;
;;;; This file contains zlib-deflate and zlib-inflate.
;;;; They use libz.dylib (the zlib version 1.2.5 shared library).
;;;; They also use the Clozure Common Lisp Foreign Function Inteface (CCL-FFI).
;;;; 


;;;
;;; copy-list-to-buf
;;; copies each byte in plist to a byte in qbuf.
;;; n is the number of bytes to copy.
;;;

(defun copy-list-to-buf (plist qbuf)
  (let ((n))
    (setf n (length plist))
    (if (> n (length qbuf)) (error "plist > qlist"))
    (dotimes (i n)
      (setf (aref qbuf i) (pop plist)))))


;;;
;;; copy-buf-to-list
;;; copies each byte in pbuf to a byte in a new list.
;;; n is the number of bytes to copy.
;;;

(defun copy-buf-to-list (pbuf n)
  (let ((qlist nil))
    (dotimes (i n)
      (push (aref pbuf i) qlist))
    (reverse qlist)))


;;;
;;; Define the buffers and register.
;;;

(defparameter src-buf nil)
(defparameter src-buf-ptr nil)
(defparameter dst-buf nil)
(defparameter dst-buf-ptr nil)
(defparameter dst-len nil)
(defparameter dst-len-ptr nil)


;;;
;;; zlib-open
;;; Opens the zlib dynamic library.
;;; To check that some functions are there:
;;; (external "_uv_deflate")
;;; (external "_uv_inflate")
;;;

(defun zlib-open ()
  (open-shared-library "../ZLIB/libz.dylib"))


;;;
;;; zlib-malloc
;;; Allocates four n-byte buffers in shared memory.
;;; Also allocates two 32-bit registers.
;;; Checks to make sure that they're there.
;;;

(defun zlib-malloc (n)
  (multiple-value-bind (lsb lsbp)
		       (make-heap-ivector n '(unsigned-byte 8))
		       (setq src-buf lsb)
		       (setq src-buf-ptr lsbp))
  (multiple-value-bind (ldb ldbp)
		       (make-heap-ivector n '(unsigned-byte 8))
		       (setq dst-buf ldb)
		       (setq dst-buf-ptr ldbp))
  (multiple-value-bind (ldl ldlp)
		       (make-heap-ivector 1 '(unsigned-byte 32))
		       (setq dst-len ldl)
		       (setq dst-len-ptr ldlp))
  (if (not (and (= n (length src-buf))
		(= n (length dst-buf))
		(= 1 (length dst-len))))
      (error "zlib-malloc failed.")))


;;;
;;; zlib-free
;;; Frees the two buffers and the register.
;;; (But what about the pointers?)
;;;

(defun zlib-free ()
  (dispose-heap-ivector src-buf)
  (dispose-heap-ivector dst-buf)
  (dispose-heap-ivector dst-len))


;;;
;;; zlib-deflate
;;; Maps xlist (uncompressed bytes) to ylist (compressed bytes).
;;; int uv_deflate (byte* dest, ulong* destLen, byte* source, ulong sourceLen);
;;; Copy the bytes from xlist into the source buffer, call _uv_deflate,
;;; check that the return code is 0 (Z_OK),
;;; then copy the bytes from the dest buffer into ylist.
;;;

(defun zlib-deflate (xlist)
  (let ((n) (err) (ylist))
    (setf n (length xlist))
    (zlib-open)
    (zlib-malloc 65536)
    (copy-list-to-buf xlist src-buf)
    (setf (aref dst-len 0) 65536)
    (setf err (external-call "_uv_deflate"
		   :address dst-buf-ptr
		   :address dst-len-ptr
		   :address src-buf-ptr
		   :unsigned-int n
		   :unsigned-int))
    (if (not (= 0 err)) (error "zlib-deflate: libz uv_deflate returned ~A." err))
    (setf n (aref dst-len 0))
    (setf ylist (copy-buf-to-list dst-buf n))
    (zlib-free)
    ylist))


;;;
;;; zlib-inflate
;;; Maps ylist (compressed bytes) to xlist (uncompressed bytes).
;;; int uv_inflate (byte* dest, ulong* destLen, byte* source, ulong sourceLen);
;;; Copy the bytes from ylist into the source buffer, call _uv_inflate,
;;; check that the return code is 0 (Z_OK),
;;; then copy the bytes from the dest buffer into xlist.
;;;

(defun zlib-inflate (ylist)
  (let ((n) (err) (xlist))
    (setf n (length ylist))
    (zlib-open)
    (zlib-malloc 262144)
    (copy-list-to-buf ylist src-buf)
    (setf (aref dst-len 0) 262144)
    (setf err (external-call "_uv_inflate"
		   :address dst-buf-ptr
		   :address dst-len-ptr
		   :address src-buf-ptr
		   :unsigned-int n
		   :unsigned-int))
    (if (not (= 0 err)) (error "zlib-inflate: libz uv_inflate returned ~A." err))
    (setf n (aref dst-len 0))
    (setf xlist (copy-buf-to-list dst-buf n))
    (zlib-free)
    xlist))


;;;
;;; zlib-okayp
;;; tests the zlib-deflate function and the zlib-inflate function.
;;; generates uncompressed bytes into xlist,
;;; calls zlib-deflate to take xlist and generate ylist,
;;; calls zlib-inflate to take ylist and generate zlist,
;;; compares xlist and zlist, returning either T or NIL.
;;;

(defun zlib-okayp ()
  (let ((xlist) (ylist) (zlist))
    (setf xlist (getfile "../Docs/rfc1950.txt"))
    (setf ylist (zlib-deflate xlist))
    (setf zlist (zlib-inflate ylist))
    (equal xlist zlist)))


