/******************************************************************************
 * xenplatform_link.h
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
#ifndef XENPLATFORM_LINK_H__
#define XENPLATFORM_LINK_H__

#include "xenplatform_api.h"

/* Define typedefs and names to go with function definitions in xsapi.h.
 * Note there are some macros and helpers in xsapi.h that go with these
 * functions. In particular the wrap/unwrap framework will need to be used.
 */
typedef NTSTATUS (*__xenbus_transaction_start_ntstatus_t)(xenbus_transaction_t *Res);

typedef VOID (*__xenbus_transaction_start_void_t)(const char *caller, xenbus_transaction_t *Res);

typedef NTSTATUS (*__xenbus_transaction_end_anonymous_t)(xenbus_transaction_t t, int abort);

typedef  NTSTATUS (*__xenbus_transaction_end_t)(const char *caller,
                                                xenbus_transaction_t t,
                                                int abort);

typedef NTSTATUS (*xenbus_write_t)(xenbus_transaction_t xbt, PCSTR path, PCSTR data);

typedef NTSTATUS (*xenbus_write_bin_t)(xenbus_transaction_t xbt, PCSTR path,
                                       PCSTR node, const void *data, size_t size);

typedef NTSTATUS (*xenbus_read_t)(xenbus_transaction_t xbt, PCSTR path,
                                  PSTR *Res);

typedef NTSTATUS (*xenbus_read_bin_t)(xenbus_transaction_t xbt, PCSTR path,
                                      PCSTR node, void **Res,
                                      size_t *size);

typedef NTSTATUS (*xenbus_ls_t)(xenbus_transaction_t xbt, PCSTR path,
                                PSTR **Res);

typedef NTSTATUS (*xenbus_printf_t)(xenbus_transaction_t xbt, PCSTR prefix,
                                    PCSTR node, PCSTR fmt, ...);

typedef NTSTATUS (*xenbus_read_int_t)(xenbus_transaction_t xbt, PCSTR prefix,
                                      PCSTR node, ULONG64 *res);

typedef struct xenbus_watch_handler* (*__xenbus_watch_path_anonymous_t)(PCSTR path,
                                                                        void (*cb)(void *data),
                                                                        void *data);

typedef struct xenbus_watch_handler* (*__xenbus_watch_path_t)(PCSTR path,
                                                              const char *cb_name,
                                                              void (*cb)(void *data),
                                                              void *data);

typedef struct xenbus_watch_handler* (*xenbus_watch_path_event_t)(PCSTR path,
                                                                  struct _KEVENT *evt);

typedef NTSTATUS (*xenbus_redirect_watch_t)(struct xenbus_watch_handler *wh,
                                            PCSTR path);

typedef void (*xenbus_unregister_watch_t)(struct xenbus_watch_handler *wh);

typedef void (*xenbus_trigger_watch_t)(struct xenbus_watch_handler *wh);

typedef NTSTATUS (*xenbus_read_domain_id_t)(xenbus_transaction_t xbt,
                                            PCSTR prefix, PCSTR node,
                                            DOMAIN_ID *res);

typedef EVTCHN_PORT (*EvtchnAllocUnbound_t)(DOMAIN_ID domid, PEVTCHN_HANDLER_CB cb,
                                            void *context);

typedef EVTCHN_PORT (*EvtchnAllocUnboundDpc_t)(DOMAIN_ID domid,
                                               PEVTCHN_HANDLER_CB cb,
                                               void *context);

typedef void (*EvtchnClose_t)(EVTCHN_PORT port);

typedef void (*EvtchnPortStop_t)(EVTCHN_PORT port);

typedef void (*EvtchnNotifyRemote_t)(__in EVTCHN_PORT port);

typedef void (*EvtchnRaiseLocally_t)(__in EVTCHN_PORT port);

typedef NTSTATUS (*xenbus_write_evtchn_port_t)(xenbus_transaction_t xbt,
                                               PCSTR prefix, PCSTR node,
                                               EVTCHN_PORT port);

typedef GRANT_REF (*GnttabGrantForeignAccess_t)(DOMAIN_ID domid,
                                                PFN_NUMBER frame,
                                                GRANT_MODE mode);

typedef NTSTATUS (*GnttabEndForeignAccess_t)(GRANT_REF ref);

typedef struct grant_cache* (*GnttabAllocCache_t)(ULONG min_population);

typedef void (*GnttabFreeCache_t)(struct grant_cache *gc);

typedef GRANT_REF (*GnttabGrantForeignAccessCache_t)(DOMAIN_ID domid,
                                                     PFN_NUMBER frame,
                                                     GRANT_MODE mode,
                                                     struct grant_cache *gc);

typedef NTSTATUS (*GnttabEndForeignAccessCache_t)(GRANT_REF ref,
                                                  struct grant_cache *gc);

typedef NTSTATUS (*xenbus_write_grant_ref_t)(xenbus_transaction_t xbt, PCSTR prefix,
                                            PCSTR node, GRANT_REF gref);

typedef NTSTATUS (*xenbus_read_grant_ref_t)(xenbus_transaction_t xbt, PCSTR prefix,
                                            PCSTR node, ALIEN_GRANT_REF *gref);

typedef NTSTATUS (*GntmapMapGrants_t)(DOMAIN_ID domid,
                                      unsigned nr_grefs,
                                      const ALIEN_GRANT_REF *grefs,
                                      GRANT_MODE mode,
                                      struct grant_map_detail **detail);

typedef void (*GntmapUnmapGrants_t)(struct grant_map_detail *detail);

typedef PMDL (*GntmapMdl_t)(struct grant_map_detail *gmd);


typedef NTSTATUS (*xenbus_read_evtchn_port_t)(xenbus_transaction_t xbt, PCSTR prefix,
                                              PCSTR node, ALIEN_EVTCHN_PORT *port);

typedef EVTCHN_PORT (*EvtchnConnectRemotePort_t)(DOMAIN_ID domid,
                                                 ALIEN_EVTCHN_PORT port,
                                                 PEVTCHN_HANDLER_CB cb,
                                                 void *context);

#define XEN_PLATFORM_FUNCTION_COUNT 38

static const char *XenPlatformFunctions[] = {
    "__xenbus_transaction_start_ntstatus",
    "__xenbus_transaction_start_void",
    "__xenbus_transaction_end_anonymous",
    "__xenbus_transaction_end",
    "xenbus_write",
    "xenbus_write_bin",
    "xenbus_read",
    "xenbus_read_bin",
    "xenbus_ls",
    "xenbus_printf",
    "xenbus_read_int",
    "__xenbus_watch_path_anonymous",
    "__xenbus_watch_path",
    "xenbus_watch_path_event",
    "xenbus_redirect_watch",
    "xenbus_unregister_watch",
    "xenbus_trigger_watch",
    "xenbus_read_domain_id",
    "EvtchnAllocUnbound",
    "EvtchnAllocUnboundDpc",
    "EvtchnClose",
    "EvtchnPortStop",
    "EvtchnNotifyRemote",
    "EvtchnRaiseLocally",
    "xenbus_write_evtchn_port",
    "GnttabGrantForeignAccess",
    "GnttabEndForeignAccess",
    "GnttabAllocCache",
    "GnttabFreeCache",
    "GnttabGrantForeignAccessCache",
    "GnttabEndForeignAccessCache",
    "xenbus_write_grant_ref",
    "xenbus_read_grant_ref",
    "GntmapMapGrants",
    "GntmapUnmapGrants",
    "GntmapMdl",
    "xenbus_read_evtchn_port",
    "EvtchnConnectRemotePort"
};

struct XenPlatformApiCalls
{
    __xenbus_transaction_start_ntstatus_t __xenbus_transaction_start_ntstatus;
    __xenbus_transaction_start_void_t __xenbus_transaction_start_void;
    __xenbus_transaction_end_anonymous_t __xenbus_transaction_end_anonymous;
    __xenbus_transaction_end_t __xenbus_transaction_end;
    xenbus_write_t xenbus_write;
    xenbus_write_bin_t xenbus_write_bin;
    xenbus_read_t xenbus_read;
    xenbus_read_bin_t xenbus_read_bin;
    xenbus_ls_t xenbus_ls;
    xenbus_printf_t xenbus_printf;
    xenbus_read_int_t xenbus_read_int;
    __xenbus_watch_path_anonymous_t __xenbus_watch_path_anonymous;
    __xenbus_watch_path_t __xenbus_watch_path;
    xenbus_watch_path_event_t xenbus_watch_path_event;
    xenbus_redirect_watch_t xenbus_redirect_watch;
    xenbus_unregister_watch_t xenbus_unregister_watch;
    xenbus_trigger_watch_t xenbus_trigger_watch;
    xenbus_read_domain_id_t xenbus_read_domain_id;
    EvtchnAllocUnbound_t EvtchnAllocUnbound;
    EvtchnAllocUnboundDpc_t EvtchnAllocUnboundDpc;
    EvtchnClose_t EvtchnClose;
    EvtchnPortStop_t EvtchnPortStop;
    EvtchnNotifyRemote_t EvtchnNotifyRemote;
    EvtchnRaiseLocally_t EvtchnRaiseLocally;
    xenbus_write_evtchn_port_t xenbus_write_evtchn_port;
    GnttabGrantForeignAccess_t GnttabGrantForeignAccess;
    GnttabEndForeignAccess_t GnttabEndForeignAccess;
    GnttabAllocCache_t GnttabAllocCache;
    GnttabFreeCache_t GnttabFreeCache;
    GnttabGrantForeignAccessCache_t GnttabGrantForeignAccessCache;
    GnttabEndForeignAccessCache_t GnttabEndForeignAccessCache;
    xenbus_write_grant_ref_t xenbus_write_grant_ref;
    xenbus_read_grant_ref_t xenbus_read_grant_ref;
    GntmapMapGrants_t GntmapMapGrants;
    GntmapUnmapGrants_t GntmapUnmapGrants;
    GntmapMdl_t GntmapMdl;
    xenbus_read_evtchn_port_t xenbus_read_evtchn_port;
    EvtchnConnectRemotePort_t EvtchnConnectRemotePort;
};

/*** XenPlatform driver access routines ***/

/* Routine to locate an exported function within xenutil.sys
 * Note that the PE headers and export table must be in non-paged
 * memory if this is called at DISPATCH_LEVEL.
 *
 * IRQL <= DISPATCH_LEVEL
 *
 * Param pBase - XenUtil base pointer returned by
 *                        a call to XenPlatformLink.
 * Param szName - Function name to locate.
 * Param ppFunctionOut - Start address of the function if found.
 *
 * Returns STATUS_SUCCESS function found 
 *        STATUS_UNSUCCESSFUL function not found
 */
NTSTATUS
XenPlatformResolveEntryPoint(VOID *pBase,
                             const char *szName,
                             VOID **ppFunctionOut);

/* Routine used to find and link to the Xen platform driver.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Param ppXenPlatformDriver - The Xen platform driver object that was refed.
 * Param ppBase - Base of the XENUTIL.SYS driver used in 
 *                  XenPlatformResolveEntryPoint
 *
 * Returns STATUS_SUCCESS driver object found and output param set
 *		   STATUS_INVALID_PARAMETER bad input
 *		   STATUS_UNSUCCESSFUL could not get driver object
 *         Other errors from ObReferenceObjectByName or ZwQuerySystemInformation
 */
NTSTATUS
XenPlatformLink(PDRIVER_OBJECT *ppXenPlatformDriver,
                VOID **ppBase);

/* Routine used to unlink from the platform driver.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Param pXenPlatformDriver - The Xen platform driver object to be derefed.
 */
VOID
XenPlatformUnlink(PDRIVER_OBJECT pXenPlatformDriver);

/* Convenience routine if the caller wants to get all the functions in
 * one call.
 *
 * IRQL = PASSIVE_LEVEL
 *
 * Example:
 *
 * struct XenPlatformApiCalls *xc;
 * GRANT_REF gref;
 *
 * xc = ExAllocatePoolWithTag(NonPagedPool, sizeof(struct xcApiCalls), 'IPAX');
 * XenPlatformRegisterApiFunctions(xc);
 * gref = xc->GnttabGrantForeignAccess(wrap_DOMAIN_ID(0), pfn, GRANT_MODE_RO);
 */
NTSTATUS
XenPlatformRegisterApiFunctions(struct XenPlatformApiCalls *pApiCalls);

#endif /* !XENPLATFORM_LINK_H__ */
