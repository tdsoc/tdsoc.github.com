/* 
//
// File name: Partial_sum.cc
// Description: Program which implements the Partial Sum Attack 
//
// Author: Francesco Aldà
// Version: 1.0
// Date: 29/08/2013
//
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <ctime>
#include <vector>

#include "Cipher.hh"
#include "Utility.hh"

using namespace std;
using namespace Cipher;
using namespace Utility;

static AES aes(128);
static Utilityclass utl;

/*
//
// IT SETS UP THREE PLAINTEXT MASKS
//
*/
void Initialize_plaintexts( uint8_t plaintext[3][16] )
{
	for ( unsigned j=0; j<16; ++j )
	{
		plaintext[0][j] = 0;
		plaintext[1][j] = 1;
		plaintext[2][j] = 5;
	}
}

/*
//
// THE MAIN PROGRAM
//
*/
int main ( int argc, const char * argv[] )
{
	cout << "\nPARTIAL SUM ATTACK on AES reduced to 6 rounds" << endl << endl;

	clock_t start,end;
	double time_meter;
	start = clock();

	// Set the seed for the PRNG (used in the generation of random keys)
	srand(time(NULL)); 

	// Fix the number of rounds
	uint8_t N_rounds = 6;
  	
	// Choose the master key
	uint8_t Key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	
	// Generate a random key
	// uint8_t Key[16];
	// for ( unsigned i=0; i<16; ++i)
	//	Key[i] = rand() % 256;
	
	// Set the chosen key for the encryption	
	aes.setKey(Key);
	
	uint8_t plaintext[3][16];
	Initialize_plaintexts(plaintext);

	uint8_t ciphertext[16];
	std::fill(ciphertext,ciphertext + 16, 0);	

	cout << "Encryption process is running..." << endl;

	// Create three vectors of 2^32 bits
	vector<bool> vect11(4294967296,0);
	vector<bool> vect21(4294967296,0);
	vector<bool> vect31(4294967296,0);

	// Set the configuration of the 6th round key bytes to guess
	uint8_t config_id = 1;

	// Encrypt the three Delta-sets
	aes.Encryption(plaintext[0],ciphertext,N_rounds,vect11,config_id);
	cout << "...1st delta set done!" << endl;
	aes.Encryption(plaintext[1],ciphertext,N_rounds,vect21,config_id);
	cout << "...2nd delta set done!" << endl;
	aes.Encryption(plaintext[2],ciphertext,N_rounds,vect31,config_id);
	cout << "...3rd delta set done!" << endl;

	end = clock();
	time_meter = ((double)(end-start))/CLOCKS_PER_SEC; 	// elapsed time in seconds

	cout << "Elapsed time encryption phase: " << time_meter << " s" << endl << endl;

	cout << "Partial Sum attack is running..." << endl;
	start = clock();

	// Initialize the guess key
	uint8_t key_guess[16];
	std::fill(key_guess,key_guess + 16, 0);

	// Run the attack!
	bool flag = aes.Partial_Sum_Attack( vect11, vect21, vect31, key_guess, config_id );
	// One should repeat this procedure for the other configurations in order to retrieve every byte of the 6th Round Key
	
	// Print the cipher key
	cout << "Master key           : ";
	utl.printVector(Key);			// Function which prints a 16-byte vector

	// Compute and print the 6th round key
	cout << "6th Round key        : ";
	aes.getRoundKey(N_rounds,Key);
	utl.printVector(Key);			// Function which prints a 16-byte vector

	if (flag)
	{
		cout << "6th Round key guessed: ";
		utl.printVector(key_guess);	// Function which prints a 16-byte vector
		cout << "The attack has been successful!" << endl;
	}
	else
	{
		cout << "The attack was not successful!" << endl;
	}

	end = clock();
	time_meter = ((double)(end-start))/CLOCKS_PER_SEC; 	// elapsed time in seconds

	cout << "Elapsed time attack phase    : " << time_meter << " s" << endl << endl;

  	return 0;
}
