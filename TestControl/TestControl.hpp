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

    HRESULT STDMETHODCALLTYPE Add(int a, int b, int * sum) override;

    HRESULT STDMETHODCALLTYPE PerformAdminTask() override;

    HRESULT STDMETHODCALLTYPE IsElevated (/*out*/BOOL * is_elevated, /*out*/BOOL * is_high_il) override;

    HRESULT STDMETHODCALLTYPE TestNetworkConnection (/*in*/BSTR host, USHORT port, /*out*/BOOL * can_access) override;

    HRESULT STDMETHODCALLTYPE CreateInstance (BOOL elevated, CLSID clsid, /*out*/IUnknown ** obj) override;

    HRESULT STDMETHODCALLTYPE TestCallback(IUnknown * obj) override;

    HRESULT STDMETHODCALLTYPE MoveMouseCursor(BOOL threaded, int x_pos, int y_pos) override;

    // IOleWindow
    HRESULT STDMETHODCALLTYPE GetWindow(/*out*/HWND* wnd) override;

    HRESULT STDMETHODCALLTYPE ContextSensitiveHelp(BOOL /*fEnterMode*/) override {
        return E_NOTIMPL;
    }

    DECLARE_REGISTRY_RESOURCEID(IDR_TestControl)

    BEGIN_COM_MAP(TestControl)
        COM_INTERFACE_ENTRY(ITestInterface)
        COM_INTERFACE_ENTRY(IOleWindow)
    END_COM_MAP()
};

OBJECT_ENTRY_AUTO(CLSID_TestControl, TestControl)
