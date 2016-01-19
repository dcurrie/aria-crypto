/* aria.h
*/

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct aria_u128_s { uint64_t left; uint64_t right; } aria_u128_t;

typedef enum aria_cryto_mode_e
{
  ENCRYPT,
  DECRYPT
} aria_cryto_mode_t;

typedef enum aria_error_code_e
{
  NO_ERROR = 0,
  ARG_BAD,
  KEY_SIZE_BAD,
  CRYPTO_MODE_BAD,
} aria_error_code_t;

typedef struct aria_key_schedule_s
{
  aria_u128_t       ek[18];
  aria_cryto_mode_t mode;
  uint32_t          rounds;
} aria_key_schedule_t;

aria_error_code_t 
aria_init_key_schedule (aria_key_schedule_t *keysched
                      , aria_u128_t        KeyLeft
                      , aria_u128_t        KeyRight
                      , aria_cryto_mode_t  mode
                      , uint32_t key_size_in_bits);

aria_u128_t 
aria_crypt (aria_key_schedule_t *ks, aria_u128_t text);

#ifdef __cplusplus
}
#endif
