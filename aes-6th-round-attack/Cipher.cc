#include <stdint.h>
#include <iostream>

#include "Cipher.hh"

namespace Cipher {

	static uint8_t const sbox[256] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
  }; 

	static uint8_t const rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  };

	// The round constant word array, Rcon[i], contains the values given by 
	// x to the power (i-1) being powers of x (x is denoted as {0x02}) in the field GF(2^8)
	// Note that i starts at 1, not 0).
  	static uint8_t const  Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

  /*
  //    __ _  __ _ _ __ ___  _ __ ___   __ _ 
  //   / _` |/ _` | '_ ` _ \| '_ ` _ \ / _` |
  //  | (_| | (_| | | | | | | | | | | | (_| |
  //   \__, |\__,_|_| |_| |_|_| |_| |_|\__,_|
  //    |___/                                 
  */
  uint8_t AES::gamma( uint8_t in ) const
  { 
	return sbox[in]; 
  }

  /*
  //   _             ____                                 
  //  (_)_ ____   __/ ___| __ _ _ __ ___  _ __ ___   __ _ 
  //  | | '_ \ \ / / |  _ / _` | '_ ` _ \| '_ ` _ \ / _` |
  //  | | | | \ V /| |_| | (_| | | | | | | | | | | | (_| |
  //  |_|_| |_|\_/  \____|\__,_|_| |_| |_|_| |_| |_|\__,_|
  */
  uint8_t AES::invGamma( uint8_t in ) const 
  { 
	return rsbox[in];
  }
 
  /* 
  //     _    _____ ____  
  //    / \  | ____/ ___| 
  //   / _ \ |  _| \___ \ 
  //  / ___ \| |___ ___) |
  // /_/   \_\_____|____/ 
  */                      
  AES::AES( unsigned const bits ) 
  : Nb(4)
  , Nr((bits>>5)+6) // divide bits by 32 and we sum 6 
  , Nk(bits>>5)     // divide bits by 32
  , keyLen(bits>>3) // divide bits by 8
  {
	// I have to insert a warning!
  }

  /* 
  //  _  __          _____                            _             
  // | |/ /___ _   _| ____|_  ___ __   __ _ _ __  ___(_) ___  _ __  
  // | ' // _ \ | | |  _| \ \/ / '_ \ / _` | '_ \/ __| |/ _ \| '_ \ 
  // | . \  __/ |_| | |___ >  <| |_) | (_| | | | \__ \ | (_) | | | |
  // |_|\_\___|\__, |_____/_/\_\ .__/ \__,_|_| |_|___/_|\___/|_| |_|
  //           |___/           |_|                                  
  //
  // This function produces Nb(Nr+1) round keys. The round keys are used in each round to encrypt the states.
  */
  void AES::keyExpansion() 
  {
    // The first round key is the key itself.
    unsigned i = 0 ;
    for ( ; i < Nk ; ++i ) 
    {
	RoundKey[i*4+0] = Key[i*4+0];
	RoundKey[i*4+1] = Key[i*4+1];
	RoundKey[i*4+2] = Key[i*4+2];
	RoundKey[i*4+3] = Key[i*4+3];
    }

    // All other round keys are found from the previous round keys.
    while ( i < (Nb * (Nr+1)) ) 
    {
	uint8_t temp[4] ;

	for ( unsigned j = 0 ; j < 4 ; ++j ) temp[j] = RoundKey[(i-1) * 4 + j];
      
	if ( i % Nk == 0 ) 
	{
        	// This function rotates the 4 bytes in a word to the left once.
        	// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
				
        	// Function RotWord()
	        uint8_t k = temp[0];
        	temp[0] = temp[1];
	        temp[1] = temp[2];
	        temp[2] = temp[3];
	        temp[3] = k ;

        	// takes a four-byte input word and applies the S-box 
        	// to each of the four bytes to produce an output word.
        	temp[0] = sbox[temp[0]] ;
		temp[1] = sbox[temp[1]] ;
		temp[2] = sbox[temp[2]] ;
		temp[3] = sbox[temp[3]] ;
		temp[0] ^= Rcon[i/Nk];
      
	}	
	else if ( Nk > 6 && i % Nk == 4 )
	{
		temp[0] = sbox[temp[0]] ;
		temp[1] = sbox[temp[1]] ;
		temp[2] = sbox[temp[2]] ;
		temp[3] = sbox[temp[3]] ;
	}

	RoundKey[i*4+0] = RoundKey[(i-Nk)*4+0] ^ temp[0] ;
	RoundKey[i*4+1] = RoundKey[(i-Nk)*4+1] ^ temp[1] ;
	RoundKey[i*4+2] = RoundKey[(i-Nk)*4+2] ^ temp[2] ;
	RoundKey[i*4+3] = RoundKey[(i-Nk)*4+3] ^ temp[3] ;
      
	++i ;
    }
  }

  /*
  //     _       _     _ ____                       _ _  __          
  //    / \   __| | __| |  _ \ ___  _   _ _ __   __| | |/ /___ _   _ 
  //   / _ \ / _` |/ _` | |_) / _ \| | | | '_ \ / _` | ' // _ \ | | |
  //  / ___ \ (_| | (_| |  _ < (_) | |_| | | | | (_| | . \  __/ |_| |
  // /_/   \_\__,_|\__,_|_| \_\___/ \__,_|_| |_|\__,_|_|\_\___|\__, |
  //                                                           |___/ 
  // This function adds the round key to the state.
  // The round key is added to the state by an XOR function.
  */
  void AES::addRoundKey( unsigned round ) 
  {
	for ( unsigned i=0 ; i < 4 ; ++i )
		for ( unsigned j=0 ; j < 4 ; ++j )
			state[j][i] ^= RoundKey[(round * 4 + i) * Nb + j];
  }
  
  /*
  //             _     _ _  __          
  //    __ _  __| | __| | |/ /___ _   _ 
  //   / _` |/ _` |/ _` | ' // _ \ | | |
  //  | (_| | (_| | (_| | . \  __/ |_| |
  //   \__,_|\__,_|\__,_|_|\_\___|\__, |
  //                              |___/ 
  */
  void AES::addKey( uint8_t const Key[16] ) 
  {
    state[0][0] ^= Key[0 +0];
    state[0][1] ^= Key[4 +0];
    state[0][2] ^= Key[8 +0];
    state[0][3] ^= Key[12+0];

    state[1][0] ^= Key[0 +1];
    state[1][1] ^= Key[4 +1];
    state[1][2] ^= Key[8 +1];
    state[1][3] ^= Key[12+1];

    state[2][0] ^= Key[0 +2];
    state[2][1] ^= Key[4 +2];
    state[2][2] ^= Key[8 +2];
    state[2][3] ^= Key[12+2];

    state[3][0] ^= Key[0 +3];
    state[3][1] ^= Key[4 +3];
    state[3][2] ^= Key[8 +3];
    state[3][3] ^= Key[12+3];
  }

  /*
  //              _   ____                       _ _  __          
  //    __ _  ___| |_|  _ \ ___  _   _ _ __   __| | |/ /___ _   _ 
  //   / _` |/ _ \ __| |_) / _ \| | | | '_ \ / _` | ' // _ \ | | |
  //  | (_| |  __/ |_|  _ < (_) | |_| | | | | (_| | . \  __/ |_| |
  //   \__, |\___|\__|_| \_\___/ \__,_|_| |_|\__,_|_|\_\___|\__, |
  //   |___/                                                |___/
  //
  */
  void AES::getRoundKey( unsigned round, uint8_t key[16] ) 
  {
	for ( unsigned i=0 ; i < 4 ; ++i )
		for ( unsigned j=0 ; j < 4 ; ++j )
			key[i*4+j] = RoundKey[(round * 4 + i) * Nb + j];
  }

  /*
  //  ____        _     ____        _            
  // / ___| _   _| |__ | __ ) _   _| |_ ___  ___ 
  // \___ \| | | | '_ \|  _ \| | | | __/ _ \/ __|
  //  ___) | |_| | |_) | |_) | |_| | ||  __/\__ \
  // |____/ \__,_|_.__/|____/ \__, |\__\___||___/
  //                          |___/              
  //
  // The subBytes Function substitutes the values in the
  // state matrix with values in the S-box sbox.
  */
  void AES::subBytes() 
  {
	for ( unsigned i=0 ; i < 4 ; ++i )
		for ( unsigned j=0 ; j < 4 ; ++j )
			state[i][j] = sbox[state[i][j]];
  }

  /*
  //  ___             ____        _     ____        _            
  // |_ _|_ ____   __/ ___| _   _| |__ | __ ) _   _| |_ ___  ___ 
  //  | || '_ \ \ / /\___ \| | | | '_ \|  _ \| | | | __/ _ \/ __|
  //  | || | | \ V /  ___) | |_| | |_) | |_) | |_| | ||  __/\__ \
  // |___|_| |_|\_/  |____/ \__,_|_.__/|____/ \__, |\__\___||___/
  //                                          |___/              
  //
  // The invSubBytes Function substitutes the values in the
  // state matrix with values in the S-box rsbox.
  */
  void AES::invSubBytes() 
  {
	for ( unsigned i=0 ; i < 4 ; ++i )
		for ( unsigned j=0 ; j < 4 ; ++j )
			state[i][j] = rsbox[state[i][j]];
  }

  /* 
  //  ____  _     _  __ _   ____                   
  // / ___|| |__ (_)/ _| |_|  _ \ _____      _____ 
  // \___ \| '_ \| | |_| __| |_) / _ \ \ /\ / / __|
  //  ___) | | | | |  _| |_|  _ < (_) \ V  V /\__ \
  // |____/|_| |_|_|_|  \__|_| \_\___/ \_/\_/ |___/
  //                                               
  // The ShiftRows() function shifts the rows in the state to the left.
  // Each row is shifted with different offset.
  // Offset = Row number. So the first row is not shifted.
  */
  void AES::shiftRows() 
  {
	uint8_t temp;

	// Rotate first row 1 columns to left	
	temp        = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp ;

	// Rotate second row 2 columns to left	
	temp        = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;
	temp        = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	// Rotate third row 3 columns to left
	temp        = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = temp;
  }

  /*
  //  ___             ____  _     _  __ _   ____                   
  // |_ _|_ ____   __/ ___|| |__ (_)/ _| |_|  _ \ _____      _____ 
  //  | || '_ \ \ / /\___ \| '_ \| | |_| __| |_) / _ \ \ /\ / / __|
  //  | || | | \ V /  ___) | | | | |  _| |_|  _ < (_) \ V  V /\__ \
  // |___|_| |_|\_/  |____/|_| |_|_|_|  \__|_| \_\___/ \_/\_/ |___/
  //                                                               
  // The invShiftRows() function shifts the rows in the state to the right.
  // Each row is shifted with different offset.
  // Offset = Row number. So the first row is not shifted.
  */
  void AES::invShiftRows() 
  {
	unsigned char temp;

	// Rotate first row 1 columns to right	
	temp        = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp;

	// Rotate second row 2 columns to right	
	temp        = state[2][0];
	state[2][0] = state[2][2]; 
	state[2][2] = temp;
	temp        = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	// Rotate third row 3 columns to right
	temp        = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp;
  }

  // xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}  
  #define xtime(x) ( (x<<1) ^ (((x>>7) & 1) * 0x1b) )
  
  /*
  //  __  __ _       ____      _                           
  // |  \/  (_)_  __/ ___|___ | |_   _ _ __ ___  _ __  ___ 
  // | |\/| | \ \/ / |   / _ \| | | | | '_ ` _ \| '_ \/ __|
  // | |  | | |>  <| |__| (_) | | |_| | | | | | | | | \__ \
  // |_|  |_|_/_/\_\\____\___/|_|\__,_|_| |_| |_|_| |_|___/
  //                                                       
  // MixColumns function mixes the columns of the state matrix
  */
  void AES::mixColumns() 
  {
	uint8_t Tmp, Tm, t;
	for ( unsigned i=0 ; i < 4 ; ++i )
	{      
		t   = state[0][i];
		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
		Tm  = state[0][i] ^ state[1][i]; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp;
		Tm  = state[1][i] ^ state[2][i]; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp;
		Tm  = state[2][i] ^ state[3][i]; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp;
		Tm  = state[3][i] ^ t          ; Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp;
	}
  }

  // Multiply is a macro used to multiply numbers in the field GF(2^8)
  #define Multiply(x,y) ( ((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))) )
  
  /*
  //  ___            __  __ _       ____      _                           
  // |_ _|_ ____   _|  \/  (_)_  __/ ___|___ | |_   _ _ __ ___  _ __  ___ 
  //  | || '_ \ \ / / |\/| | \ \/ / |   / _ \| | | | | '_ ` _ \| '_ \/ __|
  //  | || | | \ V /| |  | | |>  <| |__| (_) | | |_| | | | | | | | | \__ \
  // |___|_| |_|\_/ |_|  |_|_/_/\_\\____\___/|_|\__,_|_| |_| |_|_| |_|___/
  //                                                                      
  // MixColumns function mixes the columns of the state matrix.
  // The method used to multiply may be difficult to understand for the inexperienced.
  // Please use the references to gain more information.
  */
  void AES::invMixColumns() 
  {
	for ( unsigned i = 0 ; i < 4 ; ++i )
	{
		uint8_t a = state[0][i];
		uint8_t b = state[1][i];
		uint8_t c = state[2][i];
		uint8_t d = state[3][i];

		state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
  }

  /*
  //                        _____    ____  _        _       
  //    ___ ___  _ __  _   |_   _|__/ ___|| |_ __ _| |_ ___ 
  //   / __/ _ \| '_ \| | | || |/ _ \___ \| __/ _` | __/ _ \
  //  | (_| (_) | |_) | |_| || | (_) |__) | || (_| | ||  __/
  //   \___\___/| .__/ \__, ||_|\___/____/ \__\__,_|\__\___|
  //            |_|    |___/
  //
  */                              
  void AES::copyToState( uint8_t const in[16] ) 
  {
	// Copy the input PlainText to state array.
	for ( unsigned i=0 ; i < 4 ; ++i )
		for ( unsigned j=0 ; j < 4 ; ++j )
			state[j][i] = in[i*4+j];

  }

  /*
  //   _                 _ _____                    ____  _        _       
  //  | | ___   __ _  __| |  ___| __ ___  _ __ ___ / ___|| |_ __ _| |_ ___ 
  //  | |/ _ \ / _` |/ _` | |_ | '__/ _ \| '_ ` _ \\___ \| __/ _` | __/ _ \
  //  | | (_) | (_| | (_| |  _|| | | (_) | | | | | |___) | || (_| | ||  __/
  //  |_|\___/ \__,_|\__,_|_|  |_|  \___/|_| |_| |_|____/ \__\__,_|\__\___|
  //
  */                                                                     
  void AES::loadFromState( uint8_t out[16] ) const 
  {
	// The encryption process is over.
	// Copy the state array to output array.
	for ( unsigned i=0 ; i < 4 ; ++i )
		for ( unsigned j=0 ; j < 4 ; ++j )
			out[i*4+j] = state[j][i];
  }

  /* 
  //  _____                     _      
  // | ____|_ __   ___ ___   __| | ___ 
  // |  _| | '_ \ / __/ _ \ / _` |/ _ \
  // | |___| | | | (_| (_) | (_| |  __/
  // |_____|_| |_|\___\___/ \__,_|\___|
  //                                   
  // Cipher is the main function that encrypts the PlainText.
  */
  void AES::encode( uint8_t const in[16], uint8_t out[16] )
  {
	// Copy the input PlainText to state array.
	copyToState( in );

	// Add the First round key to the state before starting the rounds.
	addRoundKey(0); 
	
	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for ( unsigned round = 1 ; round < Nr ; ++round ) 
	{
		subBytes();   // Gamma
		shiftRows();  // lambda
		mixColumns(); // lambda
		addRoundKey(round);
	}

	// The last round is given below.
	// The MixColumns function is not here in the last round.
	subBytes();
	shiftRows();
	addRoundKey(Nr);

	// The encryption process is over.
	// Copy the state array to output array.
	loadFromState( out );
  }
  
  /*
  //  ____                     _      
  // |  _ \  ___  ___ ___   __| | ___ 
  // | | | |/ _ \/ __/ _ \ / _` |/ _ \
  // | |_| |  __/ (_| (_) | (_| |  __/
  // |____/ \___|\___\___/ \__,_|\___|
  //                                  
  // InvCipher is the main function that decrypts the CipherText.
  */
  void AES::decode( uint8_t const in[16], uint8_t out[16] ) 
  {
	// Copy the input CipherText to state array.
	for ( unsigned i=0 ; i < 4 ; ++i )
		for ( unsigned j=0 ; j < 4 ; ++j )
			state[j][i] = in[i*4 + j];

	// Add the First round key to the state before starting the rounds.
	addRoundKey(Nr); 

	// There will be Nr rounds.
	// The first Nr-1 rounds are identical.
	// These Nr-1 rounds are executed in the loop below.
	for ( unsigned round = Nr-1 ; round > 0 ; --round )	
	{
		invShiftRows();
		invSubBytes();
		addRoundKey(round);
		invMixColumns();
	}
	
	// The last round is given below.
	// The MixColumns function is not here in the last round.
	invShiftRows();
	invSubBytes();
	addRoundKey(0);

	// The decryption process is over.
	// Copy the state array to output array.
	for ( unsigned i=0 ; i < 4 ; ++i )
		for ( unsigned j=0 ; j < 4 ; ++j )
			out[i*4+j] = state[j][i];
  }

}

// EOF Cipher.cc
