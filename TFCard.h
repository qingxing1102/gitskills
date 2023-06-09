/***************************************************************************
 *                                                                         *
 *   This file was automatically generated using idlc.js                   *
 *   PLEASE DO NOT EDIT!!!!                                                *
 *                                                                         *
 ***************************************************************************/

#pragma once

/**
 @author Leo Hoo <lion@9465.net>
 */

#include "../object.h"

namespace fibjs {

class X509Cert_base;
class PKey_base;
class Buffer_base;

class TFCard_base : public object_base {
    DECLARE_CLASS(TFCard_base);

public:
    class Exchg_crType : public NType {
    public:
        virtual void fillMembers(Isolate* isolate, v8::Local<v8::Object>& retVal)
        {
            v8::Local<v8::Context> context = retVal->CreationContext();
            retVal->Set(context, isolate->NewString("cr1"), GetReturnValue(isolate->m_isolate, cr1));
            retVal->Set(context, isolate->NewString("cc"), GetReturnValue(isolate->m_isolate, cc));
            retVal->Set(context, isolate->NewString("cs"), GetReturnValue(isolate->m_isolate, cs));
        }

        virtual void fillArguments(Isolate* isolate, std::vector<v8::Local<v8::Value>>& args)
        {
            args.push_back(GetReturnValue(isolate->m_isolate, cr1));
            args.push_back(GetReturnValue(isolate->m_isolate, cc));
            args.push_back(GetReturnValue(isolate->m_isolate, cs));
        }

    public:
        obj_ptr<Buffer_base> cr1;
        obj_ptr<X509Cert_base> cc;
        obj_ptr<Buffer_base> cs;
    };

public:
    // TFCard_base
    virtual result_t init(X509Cert_base* ca, X509Cert_base* crt, PKey_base* key) = 0;
    virtual result_t exchg_cr(X509Cert_base* sc, Buffer_base* sr, obj_ptr<Exchg_crType>& retVal) = 0;
    virtual result_t verify_ss(Buffer_base* ss) = 0;
    virtual result_t read(int32_t pos, obj_ptr<Buffer_base>& retVal) = 0;
    virtual result_t write(int32_t pos, Buffer_base* data) = 0;
    virtual result_t close() = 0;
    virtual result_t get_stat(obj_ptr<NObject>& retVal) = 0;

public:
    static void s__new(const v8::FunctionCallbackInfo<v8::Value>& args)
    {
        CONSTRUCT_INIT();

        Isolate* isolate = Isolate::current();

        isolate->m_isolate->ThrowException(
            isolate->NewString("not a constructor"));
    }

public:
    static void s_init(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_exchg_cr(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_verify_ss(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_read(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_write(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_close(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_get_stat(v8::Local<v8::Name> property, const v8::PropertyCallbackInfo<v8::Value>& args);
};
}

#include "ifs/X509Cert.h"
#include "ifs/PKey.h"
#include "ifs/Buffer.h"

namespace fibjs {
inline ClassInfo& TFCard_base::class_info()
{
    static ClassData::ClassMethod s_method[] = {
        { "init", s_init, false },
        { "exchg_cr", s_exchg_cr, false },
        { "verify_ss", s_verify_ss, false },
        { "read", s_read, false },
        { "write", s_write, false },
        { "close", s_close, false }
    };

    static ClassData::ClassProperty s_property[] = {
        { "stat", s_get_stat, block_set, false }
    };

    static ClassData s_cd = {
        "TFCard", false, s__new, NULL,
        ARRAYSIZE(s_method), s_method, 0, NULL, ARRAYSIZE(s_property), s_property, 0, NULL, NULL, NULL,
        &object_base::class_info()
    };

    static ClassInfo s_ci(s_cd);
    return s_ci;
}

inline void TFCard_base::s_init(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    METHOD_NAME("TFCard.init");
    METHOD_INSTANCE(TFCard_base);
    METHOD_ENTER();

    METHOD_OVER(3, 3);

    ARG(obj_ptr<X509Cert_base>, 0);
    ARG(obj_ptr<X509Cert_base>, 1);
    ARG(obj_ptr<PKey_base>, 2);

    hr = pInst->init(v0, v1, v2);

    METHOD_VOID();
}

inline void TFCard_base::s_exchg_cr(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<Exchg_crType> vr;

    METHOD_NAME("TFCard.exchg_cr");
    METHOD_INSTANCE(TFCard_base);
    METHOD_ENTER();

    METHOD_OVER(2, 2);

    ARG(obj_ptr<X509Cert_base>, 0);
    ARG(obj_ptr<Buffer_base>, 1);

    hr = pInst->exchg_cr(v0, v1, vr);

    METHOD_RETURN();
}

inline void TFCard_base::s_verify_ss(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    METHOD_NAME("TFCard.verify_ss");
    METHOD_INSTANCE(TFCard_base);
    METHOD_ENTER();

    METHOD_OVER(1, 1);

    ARG(obj_ptr<Buffer_base>, 0);

    hr = pInst->verify_ss(v0);

    METHOD_VOID();
}

inline void TFCard_base::s_read(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<Buffer_base> vr;

    METHOD_NAME("TFCard.read");
    METHOD_INSTANCE(TFCard_base);
    METHOD_ENTER();

    METHOD_OVER(1, 1);

    ARG(int32_t, 0);

    hr = pInst->read(v0, vr);

    METHOD_RETURN();
}

inline void TFCard_base::s_write(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    METHOD_NAME("TFCard.write");
    METHOD_INSTANCE(TFCard_base);
    METHOD_ENTER();

    METHOD_OVER(2, 2);

    ARG(int32_t, 0);
    ARG(obj_ptr<Buffer_base>, 1);

    hr = pInst->write(v0, v1);

    METHOD_VOID();
}

inline void TFCard_base::s_close(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    METHOD_NAME("TFCard.close");
    METHOD_INSTANCE(TFCard_base);
    METHOD_ENTER();

    METHOD_OVER(0, 0);

    hr = pInst->close();

    METHOD_VOID();
}

inline void TFCard_base::s_get_stat(v8::Local<v8::Name> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    obj_ptr<NObject> vr;

    METHOD_NAME("TFCard.stat");
    METHOD_INSTANCE(TFCard_base);
    PROPERTY_ENTER();

    hr = pInst->get_stat(vr);

    METHOD_RETURN();
}
}
