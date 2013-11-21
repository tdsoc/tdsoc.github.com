#ifndef Utility_HH
#define Utility_HH

namespace Utility 
{

  using namespace std;

  class Utilityclass
  {
  
	public:

		Utilityclass();

		void printVector( uint8_t s[16] );

		void hex2binary( uint8_t vect[16] , std::string filename );

		void hex2binary_no_slash_n( uint8_t vect[16] , std::string filename );

		void printVector_debug( uint8_t *s , int l );

		void hex2binary_for_random( uint8_t *vect , int l );

		void Print_to_binfile( uint8_t * vect , int l, std::string filename );

		uint8_t * Read_from_binfile( std::string filename , int i, int l );

  } ;

}

#endif
