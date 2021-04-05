#lang racket

(provide
 vig-genkey
 vig-encr
 vig-decr)

(require racket/random)

;;; the size of the keyspace is the modulus and we want keys that are
;;; an integer between 0 and 25
(define shift-modulus 26)

;;; the allowed characters in a message
(define alphabet (string->list "abcdefghijklmnopqrstuvwxyz"))

;;; return integers between min and max, derived from a crypto random byte

(define (crypto_randint min max)
  (let ([y (integer-bytes->integer (crypto-random-bytes 1) #f)])
    (cond [(<= min y max) y]
          [else (crypto_randint min max)])))

;;; generate a Vigenere key of length keysize,
;;; passing in the result so that it can be compared
;;; with the requested keysize as a bound
;;; new bytes are added until the result length matches the keysize

(define (vig-genkey-bytes keysize result)
  (if (= (bytes-length result) keysize)
      result
      (vig-genkey-bytes
       keysize
       (bytes-append result
                     (integer->integer-bytes (crypto_randint 97 122) 1 #f)))))

(define (vig-genkey keysize)
  (vig-genkey-bytes keysize ""))

(define (truncate len lst)
  (cond [(null? lst) lst]
        [(> len (length lst)) lst]
        [(= len 0) '()]
        [else
         (cons (car lst) (truncate (sub1 len) (cdr lst)))]))

(define (expand-iter len lst olst nlst)
  (cond [(= len 0) nlst]
        [(null? lst) (expand-iter len olst olst nlst)]
        [else
         (expand-iter (sub1 len) (rest lst) olst (append nlst (list (first lst))))]))

(define (expand len lst)
  (expand-iter len lst lst '()))

(define (vig-encr privkey message)
  
  ;;; create the lists for map to work on by converting the input string to a list
  ;;; and in the case of the private key, expand the key so the list is the same
  ;;; size as the message, to make map over two lists possible
  
  (let* ([y (bytes->list message)]
         [k (expand (length y) (bytes->list privkey))])

    ;;; convert from list to string at the end -- might be
    ;;; inefficient?  so can run a map on the list items
        
    (list->bytes
     (map (lambda (chr keychr)
            ;;; use char->integer to get the ASCII char number,
            ;;; and then use the *position* of that letter in the alphabet
            ;;; convert back to a char
            (+
             (char->integer #\a)
             ;;; modulo the keyspace size!
             (modulo
              (+ (-
                  keychr
                  (char->integer #\a))
                 (-
                  chr
                  (char->integer #\a)))
              shift-modulus)))
          y
          k))))

(define (vig-decr privkey message)
  (let* ([y (bytes->list message)]
         [k (expand (length y) (bytes->list privkey))])
    
    (list->bytes
     (map (lambda (chr keychr)

             (+
              (char->integer #\a)
              (modulo
               (-
                (-
                 chr
                 (char->integer #\a))
                (-
                 keychr
                 (char->integer #\a))
                )
               shift-modulus)))
          y
          k))))
  
