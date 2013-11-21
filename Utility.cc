#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <string>

#include "Utility.hh"

namespace Utility 
{

	// A null constructor
	Utilityclass::Utilityclass()
	{
	}

	// Function which prints a 16 bytes vector
	void Utilityclass::printVector( uint8_t s[16] )
	{
		int i ;
		for ( i = 0; i <= 15; ++i ) 
		{
			printf("%02x", s[i]);
		}
		printf("\n");
	}

	// Hex to binary conversion of a 16 bytes vector
	void Utilityclass::hex2binary( uint8_t vect[16] , std::string filename )
	{
		ofstream myfile;
  		myfile.open (filename.c_str(), ios::app); // append
		for ( uint8_t i = 0; i < 16; ++i )
		{
        		for ( int j = 7; j >= 0; --j )
			{
                		if (vect[i] & (1 << j))
                		        myfile << "1,";
                		else
                        		myfile << "0,";
			}
		}
		myfile << "\n";
	}

	// Hex to binary conversion of a 16 bytes vector
	void Utilityclass::hex2binary_no_slash_n( uint8_t vect[16] , std::string filename )
	{
		ofstream myfile;
  		myfile.open (filename.c_str(), ios::app); // append
		for ( uint8_t i = 0; i < 16; ++i )
		{
        		for ( int j = 7; j >= 0; --j )
			{
                		if (vect[i] & (1 << j))
                		        myfile << "1,";
                		else
                        		myfile << "0,";
			}
		}
	}

	// Function which prints an l bytes vector
	void Utilityclass::printVector_debug( uint8_t *s , int l )
	{
		for ( int i = 0; i < l; ++i ) 
		{
			printf("%02x", *(s+i));
		}
		printf("\n");
	}

	// Hex to binary conversion of an n bytes vector
	void Utilityclass::hex2binary_for_random( uint8_t *vect , int l )
	{
		ofstream myfile;
  		myfile.open ("random.txt", ios::app); // append
		for ( uint8_t i = 0; i < l; ++i )
		{
        		for ( int j = 7; j >= 0; --j )
			{
                		if (*(vect+i) & (1 << j))
                		        myfile << "1,";
                		else
                        		myfile << "0,";
			}
		}
		myfile << "\n";
	}

	// Print a 16 bytes vector to a binary file
	void Utilityclass::Print_to_binfile( uint8_t * vect , int l, std::string filename )
	{
		ofstream myfile;
  		myfile.open (filename.c_str(), ios::out | ios::app | ios::binary); // append, binary mode
		
		char * buf = new char[l];
		for (int j = 0; j < l; j++)
	        	buf[j] = vect[j];

		myfile.write(buf,l);
		myfile.close();
		delete [] buf;
	}

	// Read the 16*i,...,16*i+l-1 bytes of a binary file
	uint8_t * Utilityclass::Read_from_binfile( std::string filename , int i, int l )
	{
		ifstream infile( filename.c_str(), ios::in | ios::binary );
		//size_t pter = 0;
	
		infile.seekg(l*i, infile.beg); 	// set the pointer
		//pter = infile.tellg() ; 	// get the position of the pointer
		//cout << "Pointer: " << pter << endl;

		char * buf = new char[l];
		infile.read(buf,l);

		uint8_t * output = new uint8_t[l];
		for (int j = 0; j < l; j++)
	        	output[j] = buf[j];

		infile.close();
		delete [] buf;

    		return output;
  	}

}
