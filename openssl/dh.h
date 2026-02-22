#pragma once

/*
 * Minimal DH compatibility header.
 *
 * native-tls-shim currently does not implement low-level DH primitives.
 * This header exists to satisfy includes and type references.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dh_st DH;

void DH_free(DH* dh);

#ifdef __cplusplus
}
#endif
