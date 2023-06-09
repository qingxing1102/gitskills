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

class TFCard_base;
class PCCard_base;

class aixing_base : public object_base {
    DECLARE_CLASS(aixing_base);

public:
    // aixing_base
    static result_t tf_open(exlib::string pin, obj_ptr<TFCard_base>& retVal);
    static result_t pcie_open(exlib::string passwd, obj_ptr<PCCard_base>& retVal);
    static result_t pcie_reset(exlib::string old_passwd, exlib::string new_passwd, obj_ptr<PCCard_base>& retVal);

public:
    static void s__new(const v8::FunctionCallbackInfo<v8::Value>& args)
    {
        CONSTRUCT_INIT();

        Isolate* isolate = Isolate::current();

        isolate->m_isolate->ThrowException(
            isolate->NewString("not a constructor"));
    }

public:
    static void s_static_tf_open(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_static_pcie_open(const v8::FunctionCallbackInfo<v8::Value>& args);
    static void s_static_pcie_reset(const v8::FunctionCallbackInfo<v8::Value>& args);
};
}

#include "ifs/TFCard.h"
#include "ifs/PCCard.h"

namespace fibjs {
inline ClassInfo& aixing_base::class_info()
{
    static ClassData::ClassMethod s_method[] = {
        { "tf_open", s_static_tf_open, true },
        { "pcie_open", s_static_pcie_open, true },
        { "pcie_reset", s_static_pcie_reset, true }
    };

    static ClassData s_cd = {
        "aixing", true, s__new, NULL,
        ARRAYSIZE(s_method), s_method, 0, NULL, 0, NULL, 0, NULL, NULL, NULL,
        &object_base::class_info()
    };

    static ClassInfo s_ci(s_cd);
    return s_ci;
}

inline void aixing_base::s_static_tf_open(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<TFCard_base> vr;

    METHOD_NAME("aixing.tf_open");
    METHOD_ENTER();

    METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    hr = tf_open(v0, vr);

    METHOD_RETURN();
}

inline void aixing_base::s_static_pcie_open(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<PCCard_base> vr;

    METHOD_NAME("aixing.pcie_open");
    METHOD_ENTER();

    METHOD_OVER(1, 1);

    ARG(exlib::string, 0);

    hr = pcie_open(v0, vr);

    METHOD_RETURN();
}

inline void aixing_base::s_static_pcie_reset(const v8::FunctionCallbackInfo<v8::Value>& args)
{
    obj_ptr<PCCard_base> vr;

    METHOD_NAME("aixing.pcie_reset");
    METHOD_ENTER();

    METHOD_OVER(2, 2);

    ARG(exlib::string, 0);
    ARG(exlib::string, 1);

    hr = pcie_reset(v0, v1, vr);

    METHOD_RETURN();
}
}
