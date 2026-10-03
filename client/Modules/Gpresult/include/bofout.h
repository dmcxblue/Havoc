#ifndef BOFOUT_H
#define BOFOUT_H

/*
 * Buffered BOF output engine — shared by the RSoP path (entry.cpp) and the
 * domain sweep (domain_enum.cpp). Accumulates into one heap buffer and
 * flushes through BeaconOutput; chunks only if a run exceeds OUTBUFSIZE.
 */

#define OUTBUFSIZE (256 * 1024)

void bof_output_init(void);
void bof_printf(const char* fmt, ...);
void bof_flush(void);
void bof_output_done(void);

#endif /* BOFOUT_H */
