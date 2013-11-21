#ifndef Cipher_HH
#define Cipher_HH

#include <stdint.h>
#include <stdio.h>
#include <iostream>
#include <vector>

namespace Cipher {

  using namespace std;

  class AES {

	unsigned const Nb    ;  // The number of columns comprising a state in AES. It's a constant in AES, Nb = 4
	unsigned const Nr    ;  // The number of rounds in AES Cipher.
	unsigned const Nk    ;  // The number of 32 bit words in the key.
	unsigned const keyLen;  // The lenght of the key.

	uint8_t state[4][4]   ;  // the array that holds the intermediate results during encryption.

	uint8_t RoundKey[240] ;  // The array that stores the round keys.
	uint8_t Key[32]       ;  // The Key input to the AES Program

	void keyExpansion();

  public:
  
	AES( unsigned const bits );

	void setKey( uint8_t const Key[] ) 
	{
		for ( unsigned i = 0; i < keyLen; ++i ) // 16, 24, 32
			this -> Key[i] = Key[i];
		keyExpansion();
	}

	void encode( uint8_t const in[16], uint8_t out[16] );
	void decode( uint8_t const in[16], uint8_t out[16] );
	
	/*
	//
	// Functions declared on Attack_functions.cc
	//
	*/
	void encode_N_std_rounds( uint8_t const in[16], uint8_t out[16], uint8_t N );
	void encode_N_rounds( uint8_t const in[16], uint8_t out[16], uint8_t N );
	uint32_t GetPosition_4bytes ( uint8_t byte_array[4] );
	void GetArray_4bytes ( uint32_t num , uint8_t s[4] );
	void Extract( uint8_t ciphertext[16], uint8_t config_id, uint8_t tmp[4] );
	void Fill( uint8_t k1, uint8_t k2, uint8_t k3, uint8_t k4, uint8_t config_id, uint8_t key_guess[16] );
	void Encryption( uint8_t plaintext[16], uint8_t ciphertext[16], uint8_t N_rounds, vector<bool> & vect, uint8_t config_id );
	uint8_t x2_firstrow( uint8_t c0, uint8_t c1, uint8_t k0, uint8_t k1 );
	uint8_t x3_firstrow( uint8_t x2, uint8_t c3, uint8_t k3 );
	uint8_t x4_firstrow( uint8_t x3, uint8_t c4, uint8_t k4 );
	uint8_t x2_secondrow( uint8_t c0, uint8_t c1, uint8_t k0, uint8_t k1 );
	uint8_t x3_secondrow( uint8_t x2, uint8_t c3, uint8_t k3 );
	uint8_t x4_secondrow( uint8_t x3, uint8_t c4, uint8_t k4 );
	uint8_t Total_sum( vector<bool> & vect, uint8_t k5 );
	void Update_vect_2_24_firstrow( vector<bool> & vect11, vector<bool> & vect12, uint8_t k1, uint8_t k2 );
	void Update_vect_2_16_firstrow( vector<bool> & vect12, vector<bool> & vect13, uint8_t k3 );
	void Update_vect_2_8_firstrow( vector<bool> & vect13, vector<bool> & vect14, uint8_t k4 );
	void Update_vect_2_24_secondrow( vector<bool> & vect11, vector<bool> & vect12, uint8_t k1, uint8_t k2 );
	void Update_vect_2_16_secondrow( vector<bool> & vect12, vector<bool> & vect13, uint8_t k3 );
	void Update_vect_2_8_secondrow( vector<bool> & vect13, vector<bool> & vect14, uint8_t k4 );
	bool Second_row_instance( vector<bool> & vect11, vector<bool> & vect21, vector<bool> & vect31, uint8_t k1, uint8_t k2, uint8_t k3, uint8_t k4 );
	bool Partial_Sum_Attack( vector<bool> & vect11, vector<bool> & vect21, vector<bool> & vect31, uint8_t key_guess[16], uint8_t config_id );
    
	unsigned getKeyLen() const 
	{ 
		return keyLen;
	} 

	unsigned getBits() const 
	{ 
		return keyLen<<3; 
	} 

	void addRoundKey( unsigned round );
	void addKey( uint8_t const key[16] );
	void getRoundKey( unsigned round, uint8_t key[16] );

	uint8_t gamma( uint8_t in ) const ;
	uint8_t invGamma( uint8_t in ) const ;

	void subBytes();
	void invSubBytes();

	void shiftRows();
	void invShiftRows();

	void mixColumns();            
	void invMixColumns();

	void lambda() 
	{ 
		shiftRows(); 
		mixColumns(); 
	}
    
	void invLambda() 
	{ 
		invMixColumns(); 
		invShiftRows(); 
	}

	void copyToState( uint8_t const in[16] ) ;
	void loadFromState( uint8_t out[16] ) const ;
  
  } ;

}

#endif

// EOF Cipher.hh
