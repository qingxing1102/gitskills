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

class PCCard_base : public object_base {
    DECLARE_CLASS(PCCard_base);

public:
    // PCCard_base
    virtual result_t init(X509Cert_base* ca, X509Cert_base* crt, PKey_base* key) = 0;
    virtual result_t sign(Buffer_base* data, obj_ptr<Buffer_base>& retVal) = 0;
    virtual result_t encrypt(Buffer_base* data, obj_ptr<Buffer_base>& retVal) = 0;
    virtual result_t decrypt(Buffer_base* data, obj_ptr<Buffer_base>& retVal) = 0;
    virtual result_t close() = 0;
    virtual result_t get_cert(obj_ptr<X509Cert_base>& retVal) = 0;
    virtual result_t get_ca(obj_ptr<X509Cert_base>& retVal) = 0;

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
    static void s_sign(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_encrypt(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_decrypt(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_close(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_get_cert(v8::Local<v8::Name> property, const v8::PropertyCallbackInfo<v8::Value>& args);
    static void s_get_ca(v8::Local<v8::Name> property, const v8::PropertyCallbackInfo<v8::Value>& args);
};
}

#include "ifs/X509Cert.h"
#include "ifs/PKey.h"
#include "ifs/Buffer.h"

namespace fibjs {
inline ClassInfo& PCCard_base::class_info()
{
    static ClassData::ClassMethod s_method[] = {
        { "init", s_init, false },
        { "sign", s_sign, false },
        { "encrypt", s_encrypt, false },
        { "decrypt", s_decrypt, false },
        { "close", s_close, false }
    };

    static ClassData::ClassProperty s_property[] = {
        { "cert", s_get_cert, block_set, false },
        { "ca", s_get_ca, block_set, false }
    };

    static ClassData s_cd = {
        "PCCard", false, s__new, NULL,
        ARRAYSIZE(s_method), s_method, 0, NULL, ARRAYSIZE(s_property), s_property, 0, NULL, NULL, NULL,
        &object_base::class_info()
    };

    static ClassInfo s_ci(s_cd);
    return s_ci;
}

inline void PCCard_base::s_init(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    METHOD_NAME("PCCard.init");
    METHOD_INSTANCE(PCCard_base);
    METHOD_ENTER();

    METHOD_OVER(3, 3);

    ARG(obj_ptr<X509Cert_base>, 0);
    ARG(obj_ptr<X509Cert_base>, 1);
    ARG(obj_ptr<PKey_base>, 2);

    hr = pInst->init(v0, v1, v2);

    METHOD_VOID();
}

inline void PCCard_base::s_sign(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<Buffer_base> vr;

    METHOD_NAME("PCCard.sign");
    METHOD_INSTANCE(PCCard_base);
    METHOD_ENTER();

    METHOD_OVER(1, 1);

    ARG(obj_ptr<Buffer_base>, 0);

    hr = pInst->sign(v0, vr);

    METHOD_RETURN();
}

inline void PCCard_base::s_encrypt(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<Buffer_base> vr;

    METHOD_NAME("PCCard.encrypt");
    METHOD_INSTANCE(PCCard_base);
    METHOD_ENTER();

    METHOD_OVER(1, 1);

    ARG(obj_ptr<Buffer_base>, 0);

    hr = pInst->encrypt(v0, vr);

    METHOD_RETURN();
}

inline void PCCard_base::s_decrypt(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<Buffer_base> vr;

    METHOD_NAME("PCCard.decrypt");
    METHOD_INSTANCE(PCCard_base);
    METHOD_ENTER();

    METHOD_OVER(1, 1);

    ARG(obj_ptr<Buffer_base>, 0);

    hr = pInst->decrypt(v0, vr);

    METHOD_RETURN();
}

inline void PCCard_base::s_close(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    METHOD_NAME("PCCard.close");
    METHOD_INSTANCE(PCCard_base);
    METHOD_ENTER();

    METHOD_OVER(0, 0);

    hr = pInst->close();

    METHOD_VOID();
}

inline void PCCard_base::s_get_cert(v8::Local<v8::Name> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    obj_ptr<X509Cert_base> vr;

    METHOD_NAME("PCCard.cert");
    METHOD_INSTANCE(PCCard_base);
    PROPERTY_ENTER();

    hr = pInst->get_cert(vr);

    METHOD_RETURN();
}

inline void PCCard_base::s_get_ca(v8::Local<v8::Name> property, const v8::PropertyCallbackInfo<v8::Value>& args)
{
    obj_ptr<X509Cert_base> vr;

    METHOD_NAME("PCCard.ca");
    METHOD_INSTANCE(PCCard_base);
    PROPERTY_ENTER();

    hr = pInst->get_ca(vr);

    METHOD_RETURN();
}
}
