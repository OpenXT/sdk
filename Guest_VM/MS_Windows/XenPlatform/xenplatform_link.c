/******************************************************************************
 * xenplatform_link.c
 *
 * Copyright (c) 2013 Citrix Systems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <ntddk.h>
#include <windef.h>
#pragma warning(push)
#pragma warning(disable: 4201 4214 4115)
#include <ntimage.h>
#pragma warning(pop)
#include "xenplatform_link.h"

static VOID*
XenPlatformCalcAddr(const VOID *pBase, ULONG Offset)
{
    return (VOID*)(((UCHAR*)pBase) + Offset);
}

NTSTATUS
XenPlatformResolveEntryPoint(VOID *pBase,
                             const char *szName,
                             VOID **ppFunctionOut)
{
    NTSTATUS                 Status = STATUS_SUCCESS;
    PIMAGE_DOS_HEADER        pImhDos;
    PIMAGE_NT_HEADERS        pImhNt;
    PIMAGE_DATA_DIRECTORY    pImdd;
    PIMAGE_EXPORT_DIRECTORY  pImexd;
    ULONG                    i;
    ULONG                   *pNames;
    ULONG                   *pFunctions;
    const char              *szCurrent;

    if ((pBase == NULL)||(ppFunctionOut == NULL))
        return STATUS_INVALID_PARAMETER;

    do {
        pImhDos = (PIMAGE_DOS_HEADER)pBase;
        pImhNt  = (PIMAGE_NT_HEADERS)XenPlatformCalcAddr(pImhDos, pImhDos->e_lfanew);

        pImdd = &pImhNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!pImdd->VirtualAddress) {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }

        pImexd = (PIMAGE_EXPORT_DIRECTORY)XenPlatformCalcAddr(pBase, pImdd->VirtualAddress);
        if (pImexd->NumberOfFunctions < pImexd->NumberOfNames) {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }

        pFunctions = (ULONG*)XenPlatformCalcAddr(pBase, pImexd->AddressOfFunctions);
        pNames     = (ULONG*)XenPlatformCalcAddr(pBase, pImexd->AddressOfNames);
        Status     = STATUS_UNSUCCESSFUL;

        for (i = 0; i < pImexd->NumberOfNames; i++) {
            szCurrent = (const char *)XenPlatformCalcAddr(pBase, pNames[i]);
            if (strcmp(szName, szCurrent) == 0) {
                *ppFunctionOut = (VOID*)((UCHAR*)pBase + pFunctions[i]);
                Status = STATUS_SUCCESS;
                break;
            }
        }
    } while (FALSE);

    return Status;
}

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY { // Information Class 11
#if _WIN64
    ULONG Reserved[4];
#else
    ULONG Reserved[2];
#endif
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG ModuleCount;
#if _WIN64
    ULONG Reserved;
#endif 
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

NTKERNELAPI NTSTATUS NTAPI
ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                         PVOID SystemInformation,
                         ULONG SystemInformationLength,
                         PULONG ReturnLength);

/* Routine to find the XENUTIL.SYS module.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Param ppBase - Base address of driver if found.
 *
 * Returns STATUS_SUCCESS function found 
 *         STATUS_UNSUCCESSFUL function not found
*/
static NTSTATUS
XenPlatformLocateXenUtil(VOID **ppBase)
{
    NTSTATUS  Status = STATUS_SUCCESS;
    ULONG    *pBuffer = NULL;
    VOID     *pDummy;
    VOID     *pBase = NULL;
    ULONG     LengthNeeded;
    ULONG     i;
    STRING    XenUtilStr, ModuleStr;
    PSYSTEM_MODULE_INFORMATION pSmi;

    *ppBase = NULL;
    RtlInitString(&XenUtilStr, "XENUTIL.SYS");

    do {
        Status = ZwQuerySystemInformation(SystemModuleInformation,
                                          &pDummy,
                                          0,
                                          &LengthNeeded);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        /* Double it in case other modules load before I can call again. */
        LengthNeeded *= 2;

        pBuffer = (ULONG*)ExAllocatePoolWithTag(PagedPool, LengthNeeded, 'PNEX');
        if (pBuffer == NULL) {
            Status = STATUS_NO_MEMORY;
            break;
        }
        RtlZeroMemory(pBuffer, LengthNeeded);

        Status = ZwQuerySystemInformation(SystemModuleInformation,
                                          pBuffer,
                                          LengthNeeded,
                                          NULL);
        if (!NT_SUCCESS(Status))
            break;

        pSmi = (PSYSTEM_MODULE_INFORMATION)pBuffer;

        for (i = 0; i < pSmi->ModuleCount; i++) {
            if (pSmi->Modules[i].Flags) {
                RtlInitString(&ModuleStr,
                              &pSmi->Modules[i].ImageName[pSmi->Modules[i].ModuleNameOffset]);
#if DBG
                DbgPrint("Module @%d - %.*s\n", i, ModuleStr.Length, ModuleStr.Buffer);
#endif
                if (RtlEqualString(&XenUtilStr, &ModuleStr, TRUE)) {            
                    pBase = pSmi->Modules[i].Base;
                    Status = STATUS_SUCCESS;
                    break;
                }
            }
        }

        if (pBase != NULL)
            *ppBase = pBase;

    } while (FALSE);

    if (pBuffer != NULL)
        ExFreePoolWithTag(pBuffer, 'PNEX');

    return Status;
}

NTSTATUS NTAPI
ObReferenceObjectByName(PUNICODE_STRING ObjectName,
                        ULONG Attributes,
                        PACCESS_STATE Passed,
                        ACCESS_MASK DesiredAccess,
                        POBJECT_TYPE ObjectType,
                        KPROCESSOR_MODE Access,
                        PVOID ParseContext,
                        PVOID* ObjectPtr);

extern POBJECT_TYPE *IoDriverObjectType;

NTSTATUS
XenPlatformLink(PDRIVER_OBJECT *ppXenPlatformDriver, VOID **ppBase)
{
    NTSTATUS Status;
    UNICODE_STRING DriverName;
    PDRIVER_OBJECT pDriverObject;

    if ((ppXenPlatformDriver == NULL)||(ppBase == NULL))
        return STATUS_INVALID_PARAMETER;

    *ppXenPlatformDriver = NULL;

    RtlInitUnicodeString(&DriverName, L"\\Driver\\xenevtchn");

    Status = ObReferenceObjectByName(&DriverName,
                                     OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
                                     NULL, 
                                     0,
                                     *IoDriverObjectType,
                                     KernelMode,
                                     NULL,
                                     &pDriverObject);
    if (NT_SUCCESS(Status))
        *ppXenPlatformDriver = pDriverObject;
    else
        return Status;

    Status = XenPlatformLocateXenUtil(ppBase);
    if (!NT_SUCCESS(Status)) {
        ObDereferenceObject(pDriverObject);
        *ppXenPlatformDriver = NULL;
        return Status;
    }

    return Status;
}

VOID
XenPlatformUnlink(PDRIVER_OBJECT pXenPlatformDriver)
{
    if (pXenPlatformDriver != NULL)
        ObDereferenceObject(pXenPlatformDriver);
}

NTSTATUS
XenPlatformRegisterApiFunctions(struct XenPlatformApiCalls *pApiCalls)
{
    NTSTATUS Status;
    PDRIVER_OBJECT pXenUtilDriverObject;
    int i;
    void *pXenUtilBase;
    void *pFunctionReturn[XEN_PLATFORM_FUNCTION_COUNT];

    Status = XenPlatformLink(&pXenUtilDriverObject, &pXenUtilBase);
    if (!NT_SUCCESS(Status))
        return Status;

    for (i = 0; i < XEN_PLATFORM_FUNCTION_COUNT; i++) {
        Status = XenPlatformResolveEntryPoint(pXenUtilBase, XenPlatformFunctions[i], &(pFunctionReturn[i]));
        /* If a given function cannot be found, just make sure it is NULLed out
         * so the caller knows not to use it.
         */
        if (!NT_SUCCESS(Status)) {
            DbgPrint("Failed to get function pointer for %s, %08X. Calls to this function will fail.",
                     XenPlatformFunctions[i], Status);
            pFunctionReturn[i] = NULL;
        }
    }

/* Disable cast warning, it is OK */
#pragma warning(push)
#pragma warning(disable: 4152)
    pApiCalls->__xenbus_transaction_start_ntstatus = pFunctionReturn[0];
    pApiCalls->__xenbus_transaction_start_void = pFunctionReturn[1];
    pApiCalls->__xenbus_transaction_end_anonymous = pFunctionReturn[2];
    pApiCalls->__xenbus_transaction_end = pFunctionReturn[3];
    pApiCalls->xenbus_write = pFunctionReturn[4];
    pApiCalls->xenbus_write_bin = pFunctionReturn[5];
    pApiCalls->xenbus_read = pFunctionReturn[6];
    pApiCalls->xenbus_read_bin = pFunctionReturn[7];
    pApiCalls->xenbus_ls = pFunctionReturn[8];
    pApiCalls->xenbus_printf = pFunctionReturn[9];
    pApiCalls->xenbus_read_int = pFunctionReturn[10];
    pApiCalls->__xenbus_watch_path_anonymous = pFunctionReturn[11];
    pApiCalls->__xenbus_watch_path = pFunctionReturn[12];
    pApiCalls->xenbus_watch_path_event = pFunctionReturn[13];
    pApiCalls->xenbus_redirect_watch = pFunctionReturn[14];
    pApiCalls->xenbus_unregister_watch = pFunctionReturn[15];
    pApiCalls->xenbus_trigger_watch = pFunctionReturn[16];
    pApiCalls->xenbus_read_domain_id = pFunctionReturn[17];
    pApiCalls->EvtchnAllocUnbound = pFunctionReturn[18];
    pApiCalls->EvtchnAllocUnboundDpc = pFunctionReturn[19];
    pApiCalls->EvtchnClose = pFunctionReturn[20];
    pApiCalls->EvtchnPortStop = pFunctionReturn[21];
    pApiCalls->EvtchnNotifyRemote = pFunctionReturn[22];
    pApiCalls->EvtchnRaiseLocally = pFunctionReturn[23];
    pApiCalls->xenbus_write_evtchn_port = pFunctionReturn[24];
    pApiCalls->GnttabGrantForeignAccess = pFunctionReturn[25];
    pApiCalls->GnttabEndForeignAccess = pFunctionReturn[26];
    pApiCalls->GnttabAllocCache = pFunctionReturn[27];
    pApiCalls->GnttabFreeCache = pFunctionReturn[28];
    pApiCalls->GnttabGrantForeignAccessCache = pFunctionReturn[29];
    pApiCalls->GnttabEndForeignAccessCache = pFunctionReturn[30];
    pApiCalls->xenbus_write_grant_ref = pFunctionReturn[31];
    pApiCalls->xenbus_read_grant_ref = pFunctionReturn[32];
    pApiCalls->GntmapMapGrants = pFunctionReturn[33];
    pApiCalls->GntmapUnmapGrants = pFunctionReturn[34];
    pApiCalls->GntmapMdl = pFunctionReturn[35];
    pApiCalls->xenbus_read_evtchn_port = pFunctionReturn[36];
    pApiCalls->EvtchnConnectRemotePort = pFunctionReturn[37];
#pragma warning(pop)

    XenPlatformUnlink(pXenUtilDriverObject);

    return STATUS_SUCCESS;
}