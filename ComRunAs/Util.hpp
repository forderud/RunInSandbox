#pragma once
#include <Windows.h>
#include <lsalookup.h>
#include <subauth.h> // for UNICODE_STRING
#define _NTDEF_      // to avoid redefinition errors in <ntsecapi.h>
#include <ntsecapi.h> // for LSA_HANDLE


/** LSA_HANDLE RAII wrapper */
class LsaWrap {
public:
    LsaWrap() {
    }
    ~LsaWrap() {
        if (obj) {
            LsaClose(obj);
            obj = nullptr;
        }
    }

    operator LSA_HANDLE () {
        return obj;
    }
    LSA_HANDLE* operator & () {
        return &obj;
    }

private:
    LsaWrap(const LsaWrap&) = delete;
    LsaWrap& operator = (const LsaWrap&) = delete;

    LSA_HANDLE obj = nullptr;
};
