PROJECT: 	The Partial Sum Attack on 6-round reduced AES
AUTHOR:		Aldà Francesco
VERSION:	1.0
DATE:		20/09/2013

Description:
The Partial Sum Attack on 6-round reduced AES

The Partial Sum Attack is one of the most powerful attacks on reduced-round
versions of AES. It was developed by N. Ferguson, J. Kelsey, S. Lucks,
B. Schneier, M. Stay, D. Wagner and D. Whiting in 2001.

The source code of a slightly improved version of this attack has been developed
as part of my Master Thesis in Mathematics at the University of Trento, under
the supervision of Prof. Massimiliano Sala and Dr. Riccardo Aragona. On the
repository you can find a brief explanation of the ideas behind my implementation.
If you are interested in the details of my work or you want to read my thesis,
don't hesitate to send me an email at fra_alda@yahoo.it

Even though the code I developed is not fully optimized and its performances can
be certainly further improved, we believe that an effective implementation of this
attack had not already been done before my work. Therefore, I hope you will enjoy
the code and help us to improve it!

How to compile:

g++ -O3 -Wall Cipher.cc Attack_functions.cc Utility.cc Partial_sum.cc -lm -o Partial_sum
