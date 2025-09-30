#include <hal.h>
#include "simpleserial.h"

#include <string.h>
#include <sendfn.h>
#include <stdint.h>

#include "api.h"
#include "randombytes.h"

#define NTESTS 2


// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
#define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec NAMESPACE(crypto_kem_dec)


const uint8_t canary[8] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

unsigned char key_a[CRYPTO_BYTES+16];
unsigned char key_b[CRYPTO_BYTES+16];
unsigned char pk[CRYPTO_PUBLICKEYBYTES+16];
unsigned char sendb[CRYPTO_CIPHERTEXTBYTES+16];
unsigned char sk_a[CRYPTO_SECRETKEYBYTES+16];


/* allocate a bit more for all keys and messages and
 * make sure it is not touched by the implementations.
 */

static void write_canary(uint8_t *d) {
  for (size_t i = 0; i < 8; i++) {
    d[i] = canary[i];
  }
}

static int check_canary(const uint8_t *d) {
  for (size_t i = 0; i < 8; i++) {
    if (d[i] != canary[i]) {
      return -1;
    }
  }
  return 0;
}

static void put_chunk(uint8_t* chunk, int chunk_size){
  simpleserial_put('r', chunk_size, chunk);
  uint8_t res=0; 
  while(res!='b'){
    res = getch(); 
  }
  return;
}


static void process_chunk(unsigned char array[], int chunk_index, uint8_t *current_chunk, int chunk_size){
  int j = 0; 
  for (int i=chunk_index*chunk_size; i < (chunk_index+1)*chunk_size; ++i){
    current_chunk[j] = array[i];
    j++;
  }
  return;
}


static void init_kyber()
{
  write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
  write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
  write_canary(pk); write_canary(pk+sizeof(pk)-8);
  write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
  write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);
}

static uint8_t test_keys(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) 
{
  crypto_kem_keypair(pk+8, sk_a+8);
  crypto_kem_enc(sendb+8, key_b+8, pk+8);
  simpleserial_put('r', 40, key_b);
  uint8_t res=0; 
  while(res!='b'){
    res = getch();
  }
  crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

  int chunksize = 151;
  int num_chunk = 16;
  uint8_t chunk[chunksize];

  for (int j=0; j < num_chunk; ++j){
      process_chunk(sk_a, j, chunk, chunksize);
      put_chunk(chunk, chunksize);
      }


  // simpleserial_put('r', 48, key_b);

  // if(memcmp(key_a+8, key_b+8, CRYPTO_BYTES))
  // {
  //   uint8_t ERROR_KEYS[2] = {0x33, 0x33};
  //   simpleserial_put('r', 2, ERROR_KEYS);
  //   // hal_send_str("ERROR KEYS\n");
  // }
  // else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
  //         check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
  //         check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
  //         check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
  //         check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
  // {
  //   uint8_t ERROR_canary[2] = {0x22, 0x22};
  //   simpleserial_put('r', 2, ERROR_canary);
  //   // hal_send_str("ERROR canary overwritten\n");
  // }
  // else
  // {
  //   uint8_t OK_KEYS[2] = {0x11, 0x11};
  //   simpleserial_put('r', 2, OK_KEYS);
  //   // hal_send_str("OK KEYS\n");
  // }

  return 0x00;
}


// uint8_t echo_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) 
// {
//   // hal_send_str("OK writing");
//   // uint8_t data2[2] = {0x11, 0x11};
//   uint8_t* pk_chunk;
//   for (int i = 0; i < 8; ++i){
//      pk_chunk = process_chunk(data, i, 1);
//      simpleserial_put('r', 1, pk_chunk);
//   }
//   // simpleseral_put('r', 8, data);
//   return 0x00;
// }

int main(void)
{
  //hal_setup(CLOCK_FAST);

  // marker for automated testing
  platform_init();
  init_uart();
  trigger_setup();
  simpleserial_init();

  init_kyber();

  // simpleserial_addcmd('s', 8, echo_test);
  simpleserial_addcmd('a', 0, test_keys);

    while(1){
        simpleserial_get();
    }
}



// #include "hal.h"
// #include "simpleserial.h"

// #include <string.h>
// #include <sendfn.h>
// #include <stdint.h>

// #include "api.h"
// #include "randombytes.h"


// // https://stackoverflow.com/a/1489985/1711232
// #define PASTER(x, y) x##y
// #define EVALUATOR(x, y) PASTER(x, y)
// #define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// // use different names so we can have empty namespaces
// #define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
// #define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
// #define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
// #define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
// #define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

// #define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
// #define MUPQ_crypto_kem_enc NAMESPACE(crypto_kem_enc)
// #define MUPQ_crypto_kem_dec NAMESPACE(crypto_kem_dec)


// const uint8_t canary[8] = {
//   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
// };

// unsigned char key_a[CRYPTO_BYTES+16];
// unsigned char key_b[CRYPTO_BYTES+16];
// unsigned char pk[CRYPTO_PUBLICKEYBYTES+16];
// unsigned char sendb[CRYPTO_CIPHERTEXTBYTES+16];
// unsigned char sk_a[CRYPTO_SECRETKEYBYTES+16];
// unsigned char sk_a_partial[150];


// /* allocate a bit more for all keys and messages and
//  * make sure it is not touched by the implementations.
//  */

// static void write_canary(uint8_t *d) {
//   for (size_t i = 0; i < 8; i++) {
//     d[i] = canary[i];
//   }
// }

// static int check_canary(const uint8_t *d) {
//   for (size_t i = 0; i < 8; i++) {
//     if (d[i] != canary[i]) {
//       return -1;
//     }
//   }
//   return 0;
// }

// static void put_chunk(uint8_t* chunk, int chunk_size){
//   simpleserial_put('r', chunk_size, chunk);
//   uint8_t res=0; 
//   while(res!='b'){
//     res = getch(); 
//   }
//   return;
// }


// static void process_chunk(unsigned char array[], int chunk_index, uint8_t *current_chunk, int chunk_size){
//   int j = 0; 
//   for (int i=chunk_index*chunk_size; i < (chunk_index+1)*chunk_size; ++i){
//     current_chunk[j] = array[i];
//     j++;
//   }
//   return;
// }


// static void init_kyber()
// {
//   write_canary(key_a); write_canary(key_a+sizeof(key_a)-8);
//   write_canary(key_b); write_canary(key_b+sizeof(key_b)-8);
//   write_canary(pk); write_canary(pk+sizeof(pk)-8);
//   write_canary(sendb); write_canary(sendb+sizeof(sendb)-8);
//   write_canary(sk_a); write_canary(sk_a+sizeof(sk_a)-8);
// }

// static uint8_t test_keys(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) 
// {
//   int chunksize = 151;
//   int num_chunk = 16;
//   uint8_t chunk[chunksize];

//   crypto_kem_keypair(pk+8, sk_a+8);
//   for(int i=0; i<500; ++i){
//     crypto_kem_enc(sendb+8, key_b+8, pk+8);
//     crypto_kem_dec(key_a+8, sendb+8, sk_a+8);

//     for (int j=0; j < num_chunk; ++j){
//       process_chunk(sk_a, j, chunk, chunksize);
//       put_chunk(chunk, chunksize);
//     }
//   }

//   // simpleserial_put('r', 48, key_b);

//   // if(memcmp(key_a+8, key_b+8, CRYPTO_BYTES))
//   // {
//   //   uint8_t ERROR_KEYS[2] = {0x33, 0x33};
//   //   simpleserial_put('r', 2, ERROR_KEYS);
//   //   // hal_send_str("ERROR KEYS\n");
//   // }
//   // else if(check_canary(key_a) || check_canary(key_a+sizeof(key_a)-8) ||
//   //         check_canary(key_b) || check_canary(key_b+sizeof(key_b)-8) ||
//   //         check_canary(pk) || check_canary(pk+sizeof(pk)-8) ||
//   //         check_canary(sendb) || check_canary(sendb+sizeof(sendb)-8) ||
//   //         check_canary(sk_a) || check_canary(sk_a+sizeof(sk_a)-8))
//   // {
//   //   uint8_t ERROR_canary[2] = {0x22, 0x22};
//   //   simpleserial_put('r', 2, ERROR_canary);
//   //   // hal_send_str("ERROR canary overwritten\n");
//   // }
//   // else
//   // {
//   //   uint8_t OK_KEYS[2] = {0x11, 0x11};
//   //   simpleserial_put('r', 2, OK_KEYS);
//   //   // hal_send_str("OK KEYS\n");
//   // }

//   return 0x00;
// }


// // uint8_t echo_test(uint8_t cmd, uint8_t scmd, uint8_t dlen, uint8_t* data) 
// // {
// //   // hal_send_str("OK writing");
// //   // uint8_t data2[2] = {0x11, 0x11};
// //   uint8_t* pk_chunk;
// //   for (int i = 0; i < 8; ++i){
// //      pk_chunk = process_chunk(data, i, 1);
// //      simpleserial_put('r', 1, pk_chunk);
// //   }
// //   // simpleseral_put('r', 8, data);
// //   return 0x00;
// // }

// int main(void)
// {
//   //hal_setup(CLOCK_FAST);

//   // marker for automated testing
//   platform_init();
//   init_uart();
//   trigger_setup();
//   simpleserial_init();

//   init_kyber();

//   // simpleserial_addcmd('s', 8, echo_test);
//   simpleserial_addcmd('a', 0, test_keys);

//     while(1){
//         simpleserial_get();
//     }
// }

