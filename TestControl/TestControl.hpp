#pragma once
#include "ComSupport.hpp"
#include "Resource.h"
#include "TestControl_h.h"


class ATL_NO_VTABLE TestControl :
    public CComObjectRootEx<CComMultiThreadModel>, // also compatible with single-threaded apartment
    public CComCoClass<TestControl, &CLSID_TestControl>,
    public ISimpleCalculator
{
public:
    TestControl(){
    }

    /*NOT virtual*/ ~TestControl() {
    }

    HRESULT STDMETHODCALLTYPE Add(int a, int b, int * sum) override {
        *sum = a + b;
        return S_OK;
    }

    DECLARE_REGISTRY_RESOURCEID(IDR_TestControl)

    BEGIN_COM_MAP(TestControl)
        COM_INTERFACE_ENTRY(ISimpleCalculator)
    END_COM_MAP()

private:
};

OBJECT_ENTRY_AUTO(CLSID_TestControl, TestControl)
