/* timer_e.c
*/

#include "timer_e.h"

#include <sys/time.h>

#if __APPLE__

#include <mach/mach.h>
#include <mach/mach_time.h>

double timer_e_nanoseconds (void)
{
    static double timeConvert = 0.0;
    if (timeConvert == 0.0)
    {
        mach_timebase_info_data_t timeBase;
        (void)mach_timebase_info(&timeBase);
        timeConvert = (double)timeBase.numer / (double)timeBase.denom;
    }
    return (double)mach_absolute_time() * timeConvert;
}

double timer_e_nanoseconds_gtod (void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (tv.tv_sec * 1000000000.0) + (tv.tv_usec * 1000.0);
}

#else

double timer_e_nanoseconds (void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (tv.tv_sec * 1000000000.0) + (tv.tv_usec * 1000.0);
}

#endif
