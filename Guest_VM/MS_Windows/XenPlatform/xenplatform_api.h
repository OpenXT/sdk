/******************************************************************************
 * xenplatform_api.h
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
#ifndef XENPLATFORM_API_H__
#define XENPLATFORM_API_H__

/* Various bits of stuff so that we can define wrapper types for
   e.g. event channel ports and make sure that you don't try to use
   them as ordinary integers or e.g. grant table references.  These
   are almost enforced by the compiler, and they're handy for
   documentation anyway. */

/* Create a wrapper type.  These wrap up something (usually an int
   or a pointer) in a nice type-safe way.  There are two main macros:

   MAKE_WRAPPER_PUB(name) -> create a wrapper type called name.  The
   nature of the thing wrapper is not exposed, *except* that the
   all-zeroes value is null (this makes initialisation a bit easier).
   Creates inline functions null_${name}(), which creates a null
   instance of the wrapper, and is_null_${name}(x), which tests
   whether x is a null instance.

   MAKE_WRAPPER_PRIV(name, type) -> make the contents of ${name} be of
   type ${type}, and create functions wrap_${name} and unwrap_${name}
   to access it.

   There's also a variant of MAKE_WRAPPER_PRIV called
   __MAKE_WRAPPER_PRIV, which creates __wrap_${name} and
   __unwrap_${name} instead.  The intent here is to make it easier to
   apply transformations to the thing which was wrapped.
*/

#define __MAKE_WRAPPER_PUB(name)                           \
static __inline name null_ ## name ()                      \
{                                                          \
    name ret = {{0}};                                      \
    return ret;                                            \
}
#ifdef AMD64
#define MAKE_WRAPPER_PUB(name)                             \
typedef struct {                                           \
    unsigned char __wrapped_data[8];                       \
} name;                                                    \
__MAKE_WRAPPER_PUB(name)                                   \
static __inline BOOLEAN is_null_ ## name (name x)          \
{                                                          \
    if (*(unsigned long long *)x.__wrapped_data == 0)      \
        return TRUE;                                       \
    else                                                   \
        return FALSE;                                      \
}
#else
#define MAKE_WRAPPER_PUB(name)                             \
typedef struct {                                           \
    unsigned char __wrapped_data[4];                       \
} name;                                                    \
__MAKE_WRAPPER_PUB(name)                                   \
static __inline BOOLEAN is_null_ ## name (name x)          \
{                                                          \
    if (*(unsigned *)x.__wrapped_data == 0)                \
        return TRUE;                                       \
    else                                                   \
        return FALSE;                                      \
}
#endif /* !AMD64 */

#define __MAKE_WRAPPER_PRIV(name, type)                    \
static __inline name __wrap_ ## name (type val)            \
{                                                          \
    name ret;                                              \
    *(type *)ret.__wrapped_data = val;                     \
    return ret;                                            \
}                                                          \
static __inline type __unwrap_ ## name (name x)            \
{                                                          \
    return *(type*)x.__wrapped_data;                       \
}

#define MAKE_WRAPPER_PRIV(name, type)                      \
static __inline name wrap_ ## name (type val)              \
{                                                          \
    name ret;                                              \
    *(type *)ret.__wrapped_data = val;                     \
    return ret;                                            \
}                                                          \
static __inline type unwrap_ ## name (name x)              \
{                                                          \
    return *(type*)x.__wrapped_data;                       \
}

#ifndef XSAPI
#define XSAPI DECLSPEC_IMPORT
#endif

/* ----------------------- Domain ID type -------------------------- */
/* A special type for domain IDs.  The aim here is to make it obvious
 * if someone's assumed that backends are always in dom0. */
MAKE_WRAPPER_PUB(DOMAIN_ID)
__MAKE_WRAPPER_PRIV(DOMAIN_ID, int)
/* Take an int and turn it into a DOMAIN_ID.  The 0xf001 is to make
 * uninitialised domain ids obvious.  I specifically don't want an
 * uninitialised id to show up as 0, since that's almost, but not
 * quite, always the right answer, so is unlikely to get spotted. */
static __inline DOMAIN_ID wrap_DOMAIN_ID(int x)
{
    return __wrap_DOMAIN_ID(x ^ 0xf001);
}
/* Given a DOMAIN_ID, return the integer domain id */
static __inline int unwrap_DOMAIN_ID(DOMAIN_ID x)
{
    return __unwrap_DOMAIN_ID(x) ^ 0xf001;
}
/* Construct a DOMAIN_ID for dom0. */
#define DOMAIN_ID_0() wrap_DOMAIN_ID(0)

/* --------------------------- Xenbus ------------------------------ */
/* All xenbus operations can, at present, be invoked at IRQL <=
 * DISPATCH_LEVEL.  I'd be happier if I could restrict that to
 * PASSIVE_LEVEL, though. */

/* Any operations performed inside a transaction will be exposed to
 * other domains atomically when the transaction ends (assuming it was
 * successful).  If any operation inside a transaction fails, the
 * whole transaction fails with the same error code.  These are not
 * the semantics which most people expect, and they are not those
 * exposed by the Linux equivalents of this API, but they do
 * drastically simplify error handling logic in most callers of it.
 *
 * xenbus_read() and xenbus_ls() operations performed inside a
 * transaction can, sometimes, invent results which have never
 * appeared in the store.  If this happens, the transaction will
 * always fail to commit, returning either STATUS_RETRY if no other
 * error occurs or an appropriate error value if one does.
 *
 * Most operations can be performed with a null transaction, including
 * xenbus_transaction_end(), in which case they return
 * STATUS_INSUFFICIENT_RESOURCES.
 */
MAKE_WRAPPER_PUB(xenbus_transaction_t)
struct xenbus_transaction;
__MAKE_WRAPPER_PRIV(xenbus_transaction_t, struct xenbus_transaction *)

/* The nil transaction.  Operations performed in this transaction are
 * exposed immediately and do not need an explicit transaction_end.
 * They are still atomic, however.
 *
 * Note that this is *not* the null transaction, which is reserved
 * for error situations.
 */
#define XBT_NIL __wrap_xenbus_transaction_t((struct xenbus_transaction *)1)

/* Check whether a transaction is XBT_NIL.  Returns TRUE if @xbt is
 * XBT_NIL, and FALSE otherwise.
 *
 * @xbt can be null, nil, or a valid transaction.
 *
 * Added in XE 4.1.
 */
static __inline BOOLEAN
is_nil_xenbus_transaction_t(xenbus_transaction_t xbt)
{
    if (__unwrap_xenbus_transaction_t(xbt) ==
        (struct xenbus_transaction *)1)
        return TRUE;
    else
        return FALSE;
}

/* Start a new transaction.  Returns the new transaction at *@Res.
 * This function always succeeds, and the returned transaction must
 * always be finished by xenbus_transaction_end().
 *
#ifdef XSAPI_LEGACY_XENBUS_TRANSACTION_START_RETURNS_NTSTATUS
 * The return value is somewhat subtle.  xenbus_transaction_start()
 * will always open a new transaction, and must therefore always be
 * followed by a call to xenbus_transaction_end().  However,
 * xenbus_transaction_start() may sometimes be able to detect that the
 * transaction is in some sense doomed to fail, and in that case it
 * will return a non-NT_SUCCESS() value which is the expected result
 * of trying to call xenbus_transaction_end() and committing the
 * transaction.  This is intended to allow the caller to optimise by
 * avoiding any time-consuming actions which will then be discarded
 * when the transaction aborts.  The caller is never required to look
 * at the return value of this function to achieve simple
 * correctness.
#endif
 */
XSAPI NTSTATUS __xenbus_transaction_start_ntstatus(__out xenbus_transaction_t *Res);
XSAPI VOID __xenbus_transaction_start_void(__in const char *caller, __out xenbus_transaction_t *Res);
#ifdef XSAPI_LEGACY_XENBUS_TRANSACTION_START_RETURNS_NTSTATUS
#define xenbus_transaction_start(_xbt) __xenbus_transaction_start_ntstatus(_xbt)
#else
#define xenbus_transaction_start(_xbt) __xenbus_transaction_start_void(__FUNCTION__, (_xbt))
#endif

/* End a transaction.  If @abort is 0, the transaction is committed;
 * otherwise, it is aborted, and no operations performed under it
 * will be visible to other users of the store.  This can return
 * STATUS_RETRY if some other domain made a conflicting update to
 * the store, in which case the caller should try the transaction
 * again.
 *
 * Even when this returns failure, the transaction is still finished,
 * and should not be used again.
 *
 * @t can be null but not nil.
 */
__checkReturn XSAPI NTSTATUS __xenbus_transaction_end_anonymous(xenbus_transaction_t t, int abort);
__checkReturn XSAPI NTSTATUS __xenbus_transaction_end(const char *caller,
                                                      xenbus_transaction_t t,
                                                      int abort);
#define xenbus_transaction_end(_xbt, _abort) \
        __xenbus_transaction_end(__FUNCTION__, (_xbt), (_abort))

/* XXX These should take a prefix and a node, rather than just a
   path. */

/* Write the nul-terminated string @data to @path as part of transaction
 * @xbt.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_write(xenbus_transaction_t xbt, PCSTR path, PCSTR data);

/* Write @size bytes from @data to @path/@node as part of transaction
 * @xbt.
 *
 * @path, @node, and @data must point at valid globally-mapped
 * non-pageable memory.
 *
 * @data can contain arbitrary binary data, including embedded nuls.
 *
 * @xbt can be null, nil, or a valid transaction.
 *
 * Added in XE 4.1
 */
XSAPI NTSTATUS xenbus_write_bin(xenbus_transaction_t xbt, PCSTR path,
                                PCSTR node, const void *data, size_t size);

/* Read a nul-terminated string from @path under transaction @xbt.
 * The result is returned as a nul-terminated string at *@Res, and
 * should be freed with XmFreeMemory() when you're finished with
 * it.
 *
 * @path must point at valid globally-mapped non-pageable memory.  The
 * buffer returned through *@Res will be non-pageable and globally
 * mapped.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read(xenbus_transaction_t xbt, PCSTR path,
                           __out PSTR *Res);

/* Read arbitrary data from @path/@node under transaction @xbt.  The
 * result is returned as a newly-allocated buffer at *@Res, and should
 * be freed with XmFreeMemory() when you're finished with it.  The
 * length of the buffer is returned in *@size.
 *
 * Note that *@Res is not guaranteed to be nul-terminated, and can
 * contain embedded nuls.  This is different from xenbus_read().
 *
 * @path and @node must point at valid globally-mapped non-pageable
 * memory.  The buffer returned through *@Res will be non-pageable and
 * globally mapped.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_bin(xenbus_transaction_t xbt, PCSTR path,
                               PCSTR node, __out void **Res,
                               __out size_t *size);

/* List the sub-nodes of node @path under transaction @xbt.  The
 * result is returned as a NULL-terminated array of nul-terminated
 * strings at *@Res.  Both the array and the strings referred to
 * should be released with XmFreeMemory().
 *
 * @path must point at valid globally-mapped non-pageable memory.  The
 * buffer returned through *@Res will be globally-mapped and
 * non-pageable, as will all of the strings referenced by it.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_ls(xenbus_transaction_t xbt, PCSTR path,
                         __out PSTR **Res);

/* Interprets @fmt as a printf-style format string, processes it as
 * for sprintf(), and writes the result to @prefix/@node under the
 * transaction @xbt.
 *
 * @prefix, @node, @fmt, and any pointers in the argument list which
 * must be dereferenced to interpret @fmt must point at valid
 * globally-mapped non-pageable memory.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_printf(xenbus_transaction_t xbt, PCSTR prefix,
                             PCSTR node, PCSTR fmt, ...);

/* Read a decimal integer from @prefix/@node under transaction @xbt.
 * The transaction is considered to have failed if this function
 * encounters any errors, including errors parsing @prefix/@node.
 *
 * @prefix, @node, and @res must all point at valid globally-mapped
 * non-pageable memory.
 *
 * @xbt can be null, nil, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_int(xenbus_transaction_t xbt, PCSTR prefix,
                               PCSTR node, ULONG64 *res);

struct xenbus_watch_handler;
/* Register a watch on @path in xenstore.  When @path changes, @cb
 * will be invoked from the xenbus thread with arguments @path and
 * @data.  The watch infrastructure takes a copy of @path, and so the
 * caller is free to release the storage used by its copy.  Returns a
 * pointer to a new watch handler structure on success, or NULL on
 * error.
 *
 * It is guaranteed that the watch will fire shortly after any change
 * to the node, barring errors.  It is not guaranteed that it fire
 * exactly once for every time the node is changed, or that it will
 * only fire when the node changes.
 *
 * Watches are preserved across dom0-driven save/restore.
 *
 * Watch callbacks are run at PASSIVE_LEVEL from a system thread.  Any
 * single watch handler will only be invoked from one thread at a
 * time.
 *
 * Implementation detail: At present, watch handlers are always run
 * from the same thread.  This means that only one handler can be
 * active at any time.  It is not guaranteed that this behaviour will
 * be preserved in future versions.
 *
 * Returns NULL on error.
 *
 * NOTE: __xenbus_watch_path_anonymous() is defined for ABI compatibility.
 *       New code should use the xenbus_watch_path() macro.
 */
XSAPI __checkReturn struct xenbus_watch_handler *__xenbus_watch_path_anonymous(PCSTR path,
                                                                               void (*cb)(void *data),
                                                                               void *data);
XSAPI __checkReturn struct xenbus_watch_handler *__xenbus_watch_path(PCSTR path,
                                                                     const char *cb_name,
                                                                     void (*cb)(void *data),
                                                                     void *data);
#define xenbus_watch_path(_path, _cb, _data) \
        __xenbus_watch_path((_path), #_cb, (_cb), (_data));

/* Register a watch on @path in xenstore, and arrange that
 * @evt is set whenever @path changes.  No priority increment is
 * applied.
 *
 * @path must point at valid non-pageable memory.
 *
 * @evt should usually be a notification event, rather than
 * synchronisation.  If a synchronisation event is used, note that
 * rapid changes will sometimes only signal the event once.  The event
 * can be signalled when path is unchanged, although this should be
 * rare.  @evt should remain valid until the watch is release with
 * xenbus_unregister_watch().  It is the caller's responsibility to
 * release the memory occupied by the event at that time.
 *
 * Watches are preserved across dom0 save/restore.
 *
 * Returns NULL on error.
 */
XSAPI __checkReturn struct xenbus_watch_handler *xenbus_watch_path_event(PCSTR path,
                                                                         struct _KEVENT *evt);

/* Re-direct a registered watch @wh so that it points at a new
 * location @path
 *
 * Returns STATUS_SUCCESS on success, or something else on error.  The
 * watch continues to use the old path on error.
 *
 * Note that this function does not wait for the watch to complete
 * before redirecting it, and so the watch can continue to fire on the
 * old location after xenbus_redirect_watch() completes.
 *
 * Call at IRQL < DISPATCH_LEVEL.
 */
XSAPI __checkReturn NTSTATUS xenbus_redirect_watch(struct xenbus_watch_handler *wh,
                                                   PCSTR path);

/* Release a watch allocated by xenbus_watch_path.  When this returns,
 * it is guaranteed that the final invocation of the callback due to
 * this watch has finished.
 *
 * This can be used to release watches allocated with either
 * xenbus_watch_path() or xenbus_watch_path_event().
 *
 * Be careful when unregistering watches from a late suspend handler
 * if the watch handler ever allocates a suspend token.  Allocating a
 * suspend token effectively waits for all suspend handlers to
 * complete, and before unregistering a watch you must wait for the
 * watch handler to complete, and so this can lead to deadlocks if the
 * watch handler is in its very early stages when the suspend starts.
 *
 * @wh must not be null.
 *
 * Must be invoked at PASSIVE_LEVEL.
 */
XSAPI void xenbus_unregister_watch(struct xenbus_watch_handler *wh);

/* Cause the watch @wh to fire soon in its normal context.
 * @wh is triggered as if the thing which it is watching was modified.
 *
 * @wh must not be null.
 *
 * Must be invoked at PASSIVE_LEVEL.
 */
XSAPI void xenbus_trigger_watch(struct xenbus_watch_handler *wh);

/* Read a domain ID from the store at @prefix/@node, under the
 * transaction @xbt.  Sets @res to the resulting domain ID, or
 * null_DOMAIN_ID() on error.
 *
 * Domain IDs are represented in the store by base-10 integers between
 * 0 and DOMID_FIRST_RESERVED-1, inclusive; if the value in the store
 * cannot be parsed as such, or if it is out of range, the call fails,
 * and so does the transaction.
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 *
 * @xbt may be nil, null, or a valid transaction.
 *
 * Added in XE 5.0.
 */
XSAPI NTSTATUS xenbus_read_domain_id(xenbus_transaction_t xbt,
                                     PCSTR prefix, PCSTR node,
                                     DOMAIN_ID *res);

/* ----------------------- Event channels -------------------------- */
/* Event channels are one of the primary Xen-provided inter-domain
 * communication mechanisms.  The only kind supported by xevtchn.sys
 * is an inter-domain event channel.  These have two ends in separate
 * domains and are, once established, basically symmetrical.  Either
 * end can notify over the event channel, which will cause a bit in
 * the other end's hypervisor shared info to be set and an interrupt
 * to be raised.  It is then up to the recipient domain to process the
 * event in a suitable fashion.
 *
 * Events can be temporarily masked by setting suitable bits in the
 * shared info structure.  This will prevent an interrupt being raised
 * for that event channel, but will not prevent the pending bit being
 * set.  Note that masking an event channel only prevents the local
 * event handler from being run; it is still possible to notify the
 * remote domain over the channel, and the remote event channel
 * handler will be invoked immediately (subject to masking in the
 * remote domain).
 *
 * If an event is raised several times before the recipient domain is
 * able to process it, the events will be combined and only delivered
 * once.
 *
 * EVTCHN_PORT structures remain valid across dom0-driven
 * save/restore, hibernation, and migration, but will not be
 * automatically communicated to device backends etc.  The Xen-side
 * event channel port number may change, but that should be invisible
 * to users of this API.
 */

MAKE_WRAPPER_PUB(EVTCHN_PORT)

/* Allocate a new Xen event channel and return an EVTCHN_PORT
 * describing it.  The domain @domid will be able to connect to this
 * port so that it can send and receive notifications over the event
 * channel.  When this port is notified by the remote domain, @cb will
 * be invoked with the single argument @context.  This callback will
 * be invoked directly from the event channel interrupt handler; it
 * must therefore be quick.  The callback can be invoked even when the
 * associated event has not been raised, although this should be rare.
 * Returns a null port on failure.
 *
 * The port should be released with EvtchnClose() when it is no longer
 * needed.
 *
 * Invoke from PASSIVE_LEVEL.
 */
typedef void EVTCHN_HANDLER_CB(void *Context);
typedef EVTCHN_HANDLER_CB *PEVTCHN_HANDLER_CB;
XSAPI EVTCHN_PORT EvtchnAllocUnbound(DOMAIN_ID domid, PEVTCHN_HANDLER_CB cb,
                                     void *context);

/* EvtchnAllocUnboundDpc() is analogous to EvtchnAllocUnbound(),
 * except that the callback is run from a DPC rather than directly
 * from the event channel interrupt handler.  The port can be raised
 * and notified as normal.
 *
 * There is no way to directly access a DPC port's DPC.  Several ports
 * may share a single Windows DPC; this should be transparent to
 * clients.  It is guaranteed that the callback will not be
 * simultaneously invoked on multiple CPUs.
 *
 * DPC ports cannot be masked and unmasked.  It is an error to call
 * EvtchnPortMask() or EvtchnPortUnmask() on such a port.
 *
 * Call from PASSIVE_LEVEL.
 *
 * Introduced in Orlando.
 */
XSAPI EVTCHN_PORT EvtchnAllocUnboundDpc(DOMAIN_ID domid,
                                        PEVTCHN_HANDLER_CB cb,
                                        void *context);

/* Close the event channel port @port, unregistering the handler.
 * When this returns, it is guaranteed that the last invocation of the
 * callback assigned with EvtchnAllocUnbound() or
 * EvtchnAllocUnboundDpc() has completed.
 *
 * It is not necessary to stop the port before closing it.
 *
 * @port may not be null.
 *
 * @port is invalid after this has been called.
 *
 * Invoke from PASSIVE_LEVEL.
 */
XSAPI void EvtchnClose(EVTCHN_PORT port);

/* Prevent any further invocations of the handler associated with @port,
 * and wait for any existing invocations to finish.
 *
 * It is not possible to re-start a port which has been stopped.  The
 * port must be closed with EvtchnClose() and re-created.
 *
 * EvtchnNotifyRemote(), EvtchnPortMask(), EvtchnPortUnmask(), and
 * EvtchnRaiseLocally() are all no-ops on a stopped port.
 * xenbus_write_evtchn_port() on a stopped port will return an error
 * and fail any transaction.
 *
 * @port may not be null.
 *
 * Invoke from PASSIVE_LEVEL.
 */
XSAPI void EvtchnPortStop(EVTCHN_PORT port);

/* Notify the remote domain connected to the event channel @port,
 * previously returned by EvtchnAllocUnbound().  The notification will
 * be discarded if there is no domain currently attached to the other
 * end of the event channel.
 *
 * @port may not be null.
 *
 * Can be invoked from any IRQL, holding any combination of locks.
 */
XSAPI void EvtchnNotifyRemote(__in EVTCHN_PORT port);

/* Cause an event channel to be raised locally.  Shortly after this is
 * called, the callback defined for the event will be invoked in its
 * usual context, exactly as if it had been raised in the remote
 * domain
 *
 * @port may not be null.
 *
 * Can be invoked from IRQL <= DISPATCH_LEVEL, holding any combination
 * of locks.
 */
XSAPI void EvtchnRaiseLocally(__in EVTCHN_PORT port);

/* Write the event channel port number @port to xenstore at
 * @prefix/@node under the transaction @xbt.  Users should not attempt
 * to interpret the contents of the EVTCHN_PORT structure
 * themselves.
 *
 * xenbus_write_evtchn_port() will fail the transaction and return an
 * error if @port was previously been passed to EvtchnPortStop().
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 *
 * @port must not be null.  @xbt may be nil, null, or a valid
 * transaction.
 */
XSAPI NTSTATUS xenbus_write_evtchn_port(xenbus_transaction_t xbt,
                                        PCSTR prefix, PCSTR node,
                                        EVTCHN_PORT port);

/* ------------------------- Grant tables -------------------------- */
/* Grant tables provide a mechanism by which domains can grant other
 * domains access to their memory in a controlled fashion.  Each grant
 * reference grants a particular foreign domain access to a particular
 * frame of physical memory in the local domain.  They can be either
 * read-only or read-write.
 *
 * We use a wrapper type, GRANT_REF, around the underlying
 * xen_grant_ref_t.  This has a couple of advantages:
 *
 * a) invalid grant references have an all-zero representation in
 * memory, so initialisation becomes much easier,
 * b) we can steal a few bits out of the bottom for flags, which
 * can then be used for checking that e.g. they're release back
 * to the right cache.
 * c) you get as much type safety as C can offer.
 *
 * GRANT_REFs are preserved across dom0-driver save/restore, and have
 * the same xen_grant_ref_t after recovery as they had before.
 */

/* Xen grant references are integers greater than or equal to 0.
 * GRANT_REFs are (grant_ref_t+1)<<10.  This makes sure that null
 * references are recognisable as such, and allows us to shove some
 * flags in the bottom few bits (mostly for debugging). */
/* As far as clients are concerned, the only operations on GRANT_REFs
 * are null_GRANT_REF, is_null_GRANT_REF, and xen_GRANT_REF.  They
 * cannot assume anything about the flags part of the reference. */
MAKE_WRAPPER_PUB(GRANT_REF)
__MAKE_WRAPPER_PRIV(GRANT_REF, ULONG_PTR)

typedef unsigned int xen_grant_ref_t;

/* Given a GRANT_REF, return the Xen grant_ref_t.  This is what needs
 * to be communicated to backends. */
static __inline xen_grant_ref_t xen_GRANT_REF(GRANT_REF g)
{
    ULONG_PTR res = __unwrap_GRANT_REF(g);
    return (xen_grant_ref_t)((res >> 10) - 1);
}

/* Given grant_ref_t, wrap it up. */
static __inline GRANT_REF xen_set_GRANT_REF(xen_grant_ref_t x)
{
  return __wrap_GRANT_REF((x+1)<<10);
}

/* Grants have two possible modes: read-only or read-write. */
MAKE_WRAPPER_PUB(GRANT_MODE)
MAKE_WRAPPER_PRIV(GRANT_MODE, int)
#define GRANT_MODE_RW wrap_GRANT_MODE(0)
#define GRANT_MODE_RO wrap_GRANT_MODE(1)

/* Grants domain @domid access to physical frame @frame of our memory.
 * The domain is able to map the frame into its own address space, and
 * can also use it as the target or source of grant copy operations.
 * The grant can be either read-only or read-write, according to
 * @mode.  The grant reference should be released by calling
 * GnttabEndForeignAccess() when it is no longer needed.
 *
 * Can be invoked at any IRQL holding any combination of locks.
 */
XSAPI GRANT_REF GnttabGrantForeignAccess(DOMAIN_ID domid,
                                         PFN_NUMBER frame,
                                         GRANT_MODE mode);

/* Undo the effects of GnttabGrantForeignAccess(): Stop any further
 * accesses through the reference @ref, and return it to the pool of
 * free grant references.  This can fail if the grant is still in use
 * in the other domain; in that case, it returns STATUS_DEVICE_BUSY.
 * The grant reference is not released.  The caller may try again
 * later, but there is no way to release the reference if the granted
 * domain refuses to unmap it.
 *
 * @ref must not be null, since this is likely to be the only place
 * where we can check that the caller hasn't done something stupid
 * like accidentally pushing a null reference over a ring to a backend.
 *
 * Can be called at any IRQL holding any combinations of locks.
 */
XSAPI NTSTATUS GnttabEndForeignAccess(GRANT_REF ref);

/* ------------------------- Grant caches -------------------------- */
/* The largest component of the cost of GnttabGrantForeignAccess() is
 * the synchronisation around the pool of free grant references.  This
 * can be mitigated using grant caches, which allocate batches of
 * grant references from the main pool and then return them without
 * performing any additional synchronisation.  The caller is expected
 * to ensure that a single grant cache is never used on multiple CPUs
 * at the same time.
 *
 * The cache infrastructure is responsible for moving references
 * between the cache and the main pool when necessary.
 *
 */

struct grant_cache;

/* Allocate a new grant cache.  Returns a pointer to the new cache on
 * success or NULL on failure.  The cache should be released with
 * GnttabFreeCache() when no longer needed.
 *
 * If this succeeds, it is guaranteed that at least @min_population
 * grant references can be allocated from the cache without an error.
 * References returned to the cache with GnttabEndForeignAccessCache()
 * are returned to this pool, so that it is possible to allocate
 * up to the limit, release n entries, and then allocate another n,
 * and be guaranteed to succeed.
 *
 *
 * Call at PASSIVE_LEVEL.
 */
XSAPI struct grant_cache *GnttabAllocCache(ULONG min_population);

/* Release the grant cache @gc which was previously allocated with
 * GnttabInitCache().  All references which were allocated with
 * GnttabGrantForeignAccessCache() should have been released with
 * GnttabEndForeignAccessCache() before releasing the grant_cache.
 *
 * @gc must not be null.
 *
 * Call at PASSIVE_LEVEL.
 */
XSAPI void GnttabFreeCache(struct grant_cache *gc);

/* This is basically a faster version of GnttabGrantForeignAccess()
 * with more complicated synchronisation requirements.  The caller
 * must ensure that no other CPU is simultaneously accessing the
 * cache.  The returned GRANT_REF should be released using
 * GnttabEndForeignAccessCache().
 *
 * Can be called at any IRQL holding any locks.
 *
 * Returns null_GRANT_REF() on error.
 */
XSAPI GRANT_REF GnttabGrantForeignAccessCache(DOMAIN_ID domid,
                                              PFN_NUMBER frame,
                                              GRANT_MODE mode,
                                              __inout struct grant_cache *gc);

/* Stop any further accesses through the reference @ref, and return it
 * to @gc.  This can fail if the grant is still in use in the other
 * domain; in that case, it returns STATUS_DEVICE_BUSY.  The grant
 * reference is not released, and is not available to the cache.  The
 * caller may try again later, but there is no way to release the
 * reference if the granted domain refuses to unmap it.  The caller is
 * expected to ensure that no other CPU is simultaneously accessing
 * @gc.
 *
 * @ref must not be null.
 *
 * Can be called at any IRQL holding any combination of locks.
 */
XSAPI NTSTATUS GnttabEndForeignAccessCache(GRANT_REF ref,
                                           __inout struct grant_cache *gc);

/* Write the grant reference @gref to xenstore at @prefix/@node under
 * the transaction @xbt.  This handles unwrapping the grant reference
 * automatically.
 *
 * @prefix and @node must point at valid globally-mapped non-pageable
 * memory.
 */
XSAPI NTSTATUS xenbus_write_grant_ref(xenbus_transaction_t xbt, PCSTR prefix,
                                      PCSTR node, GRANT_REF gref);

/* ----------------------- Grant map alien ------------------------- */
/* A wrapper type for grant references which have been offered to us
 * by a remote domain.  Any given ALIEN_GRANT_REF is only meaningful
 * when interpreted with respect to a particular remote DOMAIN_ID, and
 * it is the caller's responsibility to track which domain a
 * particular grant reference is measured against.
 */
MAKE_WRAPPER_PUB(ALIEN_GRANT_REF)

/* When the library maps a batch of alien grant references, it returns
 * the results as an opaque struct grant_map_detail.  This can be used
 * to obtain an MDL describing the mapping or to unmap the references.
 * They cannot be used for any other purpose.
 */
struct grant_map_detail;

/* Read an alien grant reference from @prefix/@node under transaction
 * @xbt, and store it in *@gref.  @prefix/@node is expected to contain
 * a positive base-10 integer less than 2^32.  For Windows domains,
 * the value in the store should be whatever is returned by
 * xen_GRANT_REF(); for other operating systems, it will be something
 * appropriate for that OS.
 *
 * Note that a grant reference of 0 cannot be read by this routine.
 * While that is, strictly speaking, a valid reference, it is reserved
 * for use by Xen and toolstack, and should not be used by ordinary
 * drivers.
 *
 * On error, *@gref is set to null_ALIEN_GRANT_REF().
 *
 * @xbt may be nil, null, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_grant_ref(xenbus_transaction_t xbt, PCSTR prefix,
                                     PCSTR node, ALIEN_GRANT_REF *gref);

/* Map a batch of @nr_grefs alien grant references drawn against
 * remote domain @domid into the local domain's physical address
 * space, and construct a grant_map_detail describing the mapping.
 * The grant references to map should be in a simple array at @grefs.
 * The mapping is read-only if @mode is GRANT_MODE_RO, and writable if
 * @mode is GRANT_MODE_RW.  The constructed grant_map_detail is
 * returned in *@detail.  It must be released by the caller with
 * GntmapUnmapGrants() when it is no longer needed.
 *
 * If the grant is mapped read-only and is then written to by the
 * local domain, the behaviour is undefined[1].
 *
 * On entry, the caller should ensure that *@detail is NULL.  *@detail
 * will remain NULL on error.
 *
 * This call either succeeds or fails; it will not partially succeed.
 * In particular, if *any* grant reference in @grefs is invalid, the
 * entire call fails, and no grant references are mapped.
 *
 * If the remote domain exits, migrates, or is suspended, the page is
 * effectively forked, so that the local domain retains access to it,
 * but updates made by the remote domain will no longer be visible.
 * The mapping must still be unmapped with GntmapUnmapGrants().
 *
 * If the local domain migrates or is suspended and resumed, the
 * remote page is partially unmapped.  The contents of the memory
 * visible through the mapping becomes undefined[2], and will no
 * longer reflect updates made by the remote domain, but will not
 * cause faults when accessed.  The mapping must still be unmapped
 * with GntmapUnmapGrants().
 *
 * XXX What about hibernation?
 *
 * Call from IRQL < DISPATCH_LEVEL.
 *
 * Returns STATUS_SUCCESS on success, or some other value x such that
 * NT_SUCCESS(x) is false on failure.
 *
 * [1] At present, Xen will either ignore the write completely, so the
 * memory remains unchanged, or raise a page fault against the local
 * domain.  It is not guaranteed that no other behaviours will be
 * introduced by future versions of Xen or this library.
 *
 * [2] At present, the memory will appear to be full of 0xff bytes,
 * and will ignore writes; this is subject to change in future
 * versions of Xen.
 */
XSAPI NTSTATUS GntmapMapGrants(DOMAIN_ID domid,
                               unsigned nr_grefs,
                               const ALIEN_GRANT_REF *grefs,
                               GRANT_MODE mode,
                               struct grant_map_detail **detail);

/* Unmap a batch of grant references which were previously mapped with
 * GntmapMapGrants().  The physical memory into which the grants were
 * mapped is repurposed, and accessing it will cause undefined
 * behaviour.
 *
 * @detail must be a grant_map_detail which was previously returned by
 * GntmapMapGrants() and which has not already been passed to
 * GntmapUnmapGrants().  It must not be NULL.
 *
 * The memory described by the detail structure must not be mapped
 * when this is called.  (i.e. any calls to MmMapLockedPages() on the
 * detail's MDL must have been balanced by calls to
 * MmUnmapLockedPages().)
 *
 * Call from IRQL < DISPATCH_LEVEL.
 */
XSAPI void GntmapUnmapGrants(struct grant_map_detail *detail);

/* Given a grant_map_detail @gmd which was previously returned by
 * GntmapMapGrants() and which has not already been passed to
 * GntmapUnmapGrants(), build an MDL describing the physical memory
 * into which the grants were mapped.
 *
 * The resulting MDL describes locked IO memory, and can be mapped
 * using MmMapLockedPages() or MmMapLockedPagesSpecifyCache() in the
 * usual way.  Likewise, the physical memory into which the grants
 * have been unmapped can be obtained via MmGetPfnArrayForMdl().
 *
 * The MDL must not be modified in any other way, and must not be
 * released (except via GntmapUnmapGrants()).  If the caller does map
 * the MDL, they must unmap them again before calling
 * GntmapUnmapGrants().
 *
 * It is not possible to re-grant memory which has been obtained in
 * this way.  In particular, if a PFN described by the mapping MDL is
 * passed to GnttabGrantForeignAccess() or
 * GnttabGrantForeignAccessCache(), the resulting GRANT_REF will not
 * be valid.
 *
 * The MDL is valid until the grant_map_detail is unmapped with
 * GntmapUnmapGrants().
 *
 * This routine never fails, and can be called at any IRQL.
 */
XSAPI PMDL GntmapMdl(struct grant_map_detail *gmd);

/* --------------------- Event channel alien ----------------------- */
/* A wrapper type for event channel ports which have been offered to
 * us by a remote domain.  Any given ALIEN_EVTCHN_PORT is only
 * meaningful when interpreted with respect to a particular remote
 * DOMAIN_ID, and it is the caller's responsibility to track which
 * domain a particular grant reference is measured against.
 */
MAKE_WRAPPER_PUB(ALIEN_EVTCHN_PORT)

/* Read an alien event channel port from @prefix/@node under
 * transaction @xbt, and store it in *@port.  @prefix/@node is
 * expected to contain a non-negative base-10 integer less than 2^32,
 * and this is used as the remote port number when communicating with
 * Xen.  For remote Windows VMs, the store node should have been
 * populated with xenbus_write_evtchn_port(); other guest operating
 * systems will provide analogous APIs.
 *
 * On error, *@port is set to null_ALIEN_EVTCHN_PORT().
 *
 * @xbt may be nil, null, or a valid transaction.
 */
XSAPI NTSTATUS xenbus_read_evtchn_port(xenbus_transaction_t xbt, PCSTR prefix,
                                       PCSTR node, ALIEN_EVTCHN_PORT *port);

/* Bind the alien event channel port @port in domain @domid to a local
 * event channel port, and arrange that @cb will be called with
 * argument @context shortly after the remote domain notifies the
 * port.  The local event channel port is returned.
 *
 * The local port has semantics broadly analogous to those of
 * EvtchnAllocUnboundDpc():
 *
 * -- The port cannot be masked with EvtchnPortMask(), or unmasked with
 *    EvtchnPortUnmask().
 * -- The callback is run from a DPC.  The details of how this is done
 *    are not defined; in particular, there is no guarantee that there is
 *    a one-to-one correspondence between EVTCHN_PORTs and Windows DPCs.
 * -- It is guaranteed that a single port will only fire on one CPU at
 *    a time.  However, the library may fire different ports in parallel.
 * -- The port may be fired spuriously at any time.
 * -- There is no guarantee that every notification issued by the
 *    remote will cause precisely one invocation of the callback.  In
 *    particular, if the remote notifies the port several times in quick
 *    succession, the events may be aggregated into a single callback.
 *    There is no general way to detect that this has happened.
 *
 * There is no way to run a remote port callback directly from the
 * interrupt handler.
 *
 * The remote domain may close the alien event channel port at any
 * time.  If that happens before the call to EvtchnConnectRemotePort()
 * completes, it returns an error.  If it happens after the call
 * completes, there is no way for the local domain to tell, and
 * notifications to the port are simply dropped.
 *
 * If the local domain suspend and resumes, migrates, or hibernates
 * and restores, the library will attempt to automatically reconnect
 * the port.  This may, of course, fail, in which case we behave as if
 * the remote domain had closed the port.
 *
 * The port should be closed with EvtchnClose() once it is no longer
 * needed.
 *
 * Call at PASSIVE_LEVEL.
 */
XSAPI EVTCHN_PORT EvtchnConnectRemotePort(DOMAIN_ID domid,
                                          ALIEN_EVTCHN_PORT port,
                                          PEVTCHN_HANDLER_CB cb,
                                          void *context);

/* Used with above routines to free returned memory blocks */
__inline VOID XmFreeMemory(PVOID block)
{
    if (block != NULL)
        ExFreePoolWithTag(block, 'xenm');
}

#endif /* !XENPLATFORM_API_H__ */
