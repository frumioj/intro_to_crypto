#lang racket

(provide
 shift-genkey
 shift-enc
 shift-dec)

(require racket/random)

;;; the size of the keyspace is the modulus and we want keys that are
;;; an integer between 0 and 25
(define shift-modulus 26)

;;; the allowed characters in a message
(define alphabet (string->list "abcdefghijklmnopqrstuvwxyz"))

;;; return an integer from 0-25, derived from 4 crypto random bytes
;;; by creating a 4-byte integer and then computing it modulo
;;; the length of the alphabet, to give a key within the range
(define (shift-genkey)
  (modulo (integer-bytes->integer (crypto-random-bytes 4) #f) shift-modulus))

(define (shift-encr privkey message)
  
  ;;; create the list for map to work on by converting the input string to a list
  (let ([y (string->list message)])
    ;;; convert from list to string at the end -- might be
    ;;; inefficient?  so can run a map on the list items
    (list->string
     (map (lambda (char)
            ;;; use char->integer to get the ASCII char number,
            ;;; and then use the *position* of that letter in the alphabet
            ;;; convert back to a char
            (integer->char
             (+
              (char->integer #\a)
              ;;; modulo the keyspace size!
              (modulo
               (+ privkey
                  (-
                   (char->integer char)
                   (char->integer #\a)))
               shift-modulus))))
          y))))

(define (shift-decr privkey message)
  (let ([y (string->list message)])
    (list->string
     (map (lambda (char)
            (integer->char
             (+
              (char->integer #\a)
              (modulo
               (-
                (-
                 (char->integer char)
                 (char->integer #\a))
                privkey)
               shift-modulus))))
          y))))
  
