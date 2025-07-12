#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} datap;

typedef struct {
    char * original; /* the original buffer [so we can free it] */
    char * buffer;   /* current pointer into our buffer */
    int    length;   /* remaining length of data */
    int    size;     /* total size of this buffer */
} formatp;

// the rest was taken from https://github.com/trustedsec/COFFLoader/blob/main/beacon_compatibility.c. credit goes to them
inline UINT32 swap_endianess( UINT32 indata )
{
    UINT32 testint = 0xaabbccdd;
    UINT32 outint  = indata;

    if (((unsigned char*)&testint)[0] == 0xdd)
    {
        ((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
    }
    return outint;
}

inline char* beacon_compatibility_output = NULL;
inline int beacon_compatibility_size = 0;
inline int beacon_compatibility_offset = 0;

inline void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL) {
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
    return;
}

inline int BeaconDataInt(datap* parser) {
    UINT32 fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

inline short BeaconDataShort(datap* parser) {
    UINT16 retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

inline int BeaconDataLength(datap* parser) {
    return parser->length;
}

inline char* BeaconDataExtract(datap* parser, int* size) {
    UINT32 length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }
    memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }
    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }
    return outdata;
}

/* format API */

inline void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }
    format->original = (char*)calloc(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

inline void BeaconFormatReset(formatp* format) {
    memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = format->size;
    return;
}

inline void BeaconFormatFree(formatp* format) {
    if (format == NULL) {
        return;
    }
    if (format->original) {
        free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

inline void BeaconFormatAppend(formatp* format, char* text, int len) {
    memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;
    return;
}

inline void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    /*Take format string, and sprintf it into here*/
    va_list args;
    int length = 0;

    va_start(args, fmt);
    length = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    if (format->length + length > format->size) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(format->buffer, length, fmt, args);
    va_end(args);
    format->length += length;
    format->buffer += length;
    return;
}


inline char* BeaconFormatToString(formatp* format, int* size) {
    *size = format->length;
    return format->original;
}

inline void BeaconFormatInt(formatp* format, int value) {
    UINT32 indata = value;
    UINT32 outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

inline void BeaconPrintf(int type, char* fmt, ...) {
    /* Change to maintain internal buffer, and return after done running. */
    va_list VaList = { 0 };

    va_start(VaList, fmt);
    vprintf(fmt, VaList);
    va_end(VaList);
}

inline void BeaconOutput(int type, char* data, int len)
{
    puts(data);
}

/* Token Functions */

inline BOOL BeaconUseToken(HANDLE token) {
    /* Leaving this to be implemented by people needing/wanting it */
    return TRUE;
}

inline void BeaconRevertToken(void) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

inline BOOL BeaconIsAdmin(void) {
    /* Leaving this to be implemented by people needing it */
    return FALSE;
}

/* Injection/spawning related stuffs
 *
 * These functions are basic placeholders, and if implemented into something
 * real should be just calling internal functions for your tools. */
inline void BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

inline BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo) {
    /* Leaving this to be implemented by people needing/wanting it */
    return FALSE;
}

inline void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char * arg, int a_len)
{
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

inline void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len)
{
    /* Leaving this to be implemented by people needing/wanting it */
    return;
}

inline void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo)
{
    (void)CloseHandle(pInfo->hThread);
    (void)CloseHandle(pInfo->hProcess);
    return;
}

inline BOOL toWideChar(char* src, wchar_t* dst, int max)
{
    /* Leaving this to be implemented by people needing/wanting it */
    return FALSE;
}

inline char* BeaconGetOutputData(int *outsize)
{
    char* outdata = beacon_compatibility_output;

    if ( outsize )
        *outsize = beacon_compatibility_size;

    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;

    return outdata;
}

#endif //BEACON_H
