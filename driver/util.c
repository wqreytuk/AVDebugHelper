/*++

Module Name:

    util.c

Notice:
    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
    (http://www.microsoft.com/opensource/licenses.mspx)


--*/

#include "pch.h"
#include "tdriver.h"

void TdSetCallContext (
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo,
    _In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
)
{
    PTD_CALL_CONTEXT CallContext;

    CallContext = (PTD_CALL_CONTEXT)ExAllocatePoolWithTag(
        PagedPool, sizeof(TD_CALL_CONTEXT), TD_CALL_CONTEXT_TAG
    );

    if (CallContext == NULL)
    {
        return;
    }

    CallContext->CallbackRegistration = CallbackRegistration;
    CallContext->Operation  = PreInfo->Operation;
    CallContext->Object     = PreInfo->Object;
    CallContext->ObjectType = PreInfo->ObjectType;

    PreInfo->CallContext = CallContext;
}

void TdCheckAndFreeCallContext (
    _Inout_ POB_POST_OPERATION_INFORMATION PostInfo,
    _In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
)
{
    PTD_CALL_CONTEXT CallContext = (PTD_CALL_CONTEXT)PostInfo->CallContext;

    if (CallContext != NULL)
    {
        TD_ASSERT (CallContext->CallbackRegistration == CallbackRegistration);

        TD_ASSERT (CallContext->Operation  == PostInfo->Operation);
        TD_ASSERT (CallContext->Object     == PostInfo->Object);
        TD_ASSERT (CallContext->ObjectType == PostInfo->ObjectType);

        ExFreePoolWithTag (CallContext, TD_CALL_CONTEXT_TAG);
    }
}

