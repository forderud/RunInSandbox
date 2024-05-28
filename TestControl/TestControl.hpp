#pragma once
#include "ComSupport.hpp"
#include "Resource.h"
#include "TestControl_h.h"


class ATL_NO_VTABLE TestControl :
    public CComObjectRootEx<CComMultiThreadModel>, // also compatible with single-threaded apartment
    public CComCoClass<TestControl, &CLSID_TestControl>,
    public ITestInterface,
    public IOleWindow
{
public:
    TestControl();

    /*NOT virtual*/ ~TestControl();

    HRESULT IsElevated (/*out*/VARIANT_BOOL * is_elevated, /*out*/VARIANT_BOOL * is_high_il) override;

    HRESULT GetUsername(/*out*/BSTR* username) override;

    HRESULT Add(int a, int b, int * sum) override;

    HRESULT PerformAdminTask() override;

    HRESULT TestNetworkConnection (/*in*/BSTR host, USHORT port, /*out*/VARIANT_BOOL * can_access) override;

    HRESULT CreateInstance (VARIANT_BOOL elevated, CLSID clsid, /*out*/IUnknown ** obj) override;

    HRESULT TestCallback(IUnknown * obj) override;

    HRESULT MoveMouseCursor(VARIANT_BOOL threaded, int x_pos, int y_pos) override;

    // IOleWindow
    HRESULT GetWindow(/*out*/HWND* wnd) override;

    HRESULT ContextSensitiveHelp(BOOL /*fEnterMode*/) override {
        return E_NOTIMPL;
    }

    DECLARE_REGISTRY_RESOURCEID(IDR_TestControl)

    BEGIN_COM_MAP(TestControl)
        COM_INTERFACE_ENTRY(ITestInterface)
        COM_INTERFACE_ENTRY(IOleWindow)
    END_COM_MAP()
};

OBJECT_ENTRY_AUTO(CLSID_TestControl, TestControl)
