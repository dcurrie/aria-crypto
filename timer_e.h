/* timer_e.h
*/

#ifdef __cplusplus
extern "C" {
#endif


#if __APPLE__
double timer_e_nanoseconds_gtod (void);
#endif

double timer_e_nanoseconds (void);


#ifdef __cplusplus
}
#endif
