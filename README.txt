PROJECT: 	The Partial Sum Attack on 6-round reduced AES
AUTHOR:		Aldà Francesco
VERSION:	1.0
DATE:		20/09/2013

How to compile:

g++ -O3 -Wall Cipher.cc Attack_functions.cc Utility.cc Partial_sum.cc -lm -o Partial_sum
