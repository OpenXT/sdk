/******************************************************************************
 * xenplatform_samples.c
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

/* This file contains samples and snippets for reference purposes. It is
 * not meant to be compiled as.
 */

/**** XenBus/XenStore ****/

/* Write a grant ref and ec port to xenstore in a transaction for whatever
 * your pThing is. Also some non-transaction read/write stuff.
 */
static NTSTATUS
GrantAndEventChannelInATransaction(CHAR *pFrontendPath, struct THING *pThing)
{
    NTSTATUS Status;
    CHAR *pMyData;
    xenbus_transaction_t Xbt;
    
    do {
        xenbus_transaction_start(&Xbt);
        xenbus_write_grant_ref(Xbt, pFrontendPath, "ring-ref",
                               pThing->RingGrantRef);

        xenbus_write_evtchn_port(Xbt, pFrontendPath, "event-channel",
                                 pThing->EvtchnPort);

        Status = xenbus_transaction_end(Xbt, 0);

    } while (Status == STATUS_RETRY);

    if (Status != STATUS_SUCCESS) {
        DbgPrint("Failed to end transaction, 0x%08x.\n", Status);
        /* Handle failure */
    }

    /* A write and read w/o a transaction */
    xenbus_write(XBT_NIL, "drivers/mydriver", "1.2.3.4");

    Status = xenbus_read(XBT_NIL, "drivers/mydriver/mydata", &pMyData);
    if (NT_SUCCESS(Status)) {
        DbgPrint("Read MyData: %s\n", pMyData);
        XmFreeMemory(pMyData);
    }

    /* ... */
}

/* The following is a thread that waits for changes to "mydevice"
 * until told to shutdown.
 */
static VOID
XenbusWatchSomethingThread(void *pCtxt)
{
    struct THING *pThing = pCtxt;
    struct xenbus_watch_handler *pWatch;
    KEVENT Event;

    KeInitializeEvent(&Event,
                      NotificationEvent,
                      FALSE);

    pWatch = xenbus_watch_path_event("mydevice", &Event);
    if (pWatch == NULL) {
        /* Probably can't run your thread w/o a watch to watch */
        DbgPrint("Failed to watch xenbus device area!\n"));
        return;
    }

    while (KeepRunning) {
        KeWaitForSingleObject(&Event,
                              Executive,
                              KernelMode,
                              FALSE,
                              NULL);
        KeClearEvent(&Event);
        /* "mydevice" was changed, do something appropriate here */
        /* ... */
    }

    xenbus_unregister_watch(pWatch);
    DbgPrint(("Xenbus reprobe thread exitting?\n"));
    return STATUS_SUCCESS;
}

/**** Event Channels ****/

/* The following set of routines register a DPC for an event channel.
 * This is the simplest way to use event channels and not have to
 * deal with ISR context.
 */

static VOID
MyEventChannelCallback(PVOID pContext)
{
    /* Handle specifics when your event channel is fired. Note
     * this is a DPC running at DISPATCH_LEVEL.
     */
}

static VOID
CleanupMyEventChannel(struct THING *pThing)
{
    EvtchnClose(pThing->EventChannelPort);
    pThing->EventChannelPort = NULL;
}

static VOID
SetupMyEventChannel(struct THING *pThing)
{
    NTSTATUS Status;

    /* Returns a EVTCHN_PORT, a handle to the new EC */
    pThing->EventChannelPort =
        EvtchnAllocUnboundDpc(pThing->BackendDomid,
                              MyEventChannelCallback,
                              pThing);
    if (is_null_EVTCHN_PORT(pThing->EventChannelPort))
    {
        /* Handle failure to allocated EC */
    }

    /* Usually a guest creates an EC port and writes it
     * to xenstore so the backend can find it and connect
     * to it.
     */
    Status = xenbus_write_evtchn_port(XBT_NIL,
                                      pThing->pPath,
                                      "event-channel",
                                      pThing->EventChannelPort);
    if (!NT_SUCCESS(Status)) {
        /* This is unlikely and probably bad. Using transactions
         * as in GrantAndEventChannelInATransaction() above would
         * be a more robust way to do this.
         */
        CleanupMyEventChannel(pThing);
    }
}

static VOID
DriverRoutineDoingSomeNormalProcessing(struct THING *pThing)
{
    /* ... */

    /* During processing in your driver, you may want to fire an event
     * locally to get your DPC to run. This can be done with the EC
     * framework.
     */
    EvtchnRaiseLocally(pThing->EventChannelPort);

    /* ... */

    /* During processing in your driver, you may want to kick the other
     * end and tell it that something occured.
     */
    EvtchnNotifyRemote(pThing->EventChannelPort);

    /* ... */

}

/**** Grant Tables ****/

/* This routine initializes grants using the cache routines. If the
 * total grant size is known up front it is better to use the cache
 * routines since later calls to allocated grefs are guaranteed to 
 * succeed.
 */
static NTSTATUS
InitializeMyGrants(struct THING *pThing)
{
    PFN_NUMBER Pfn;

    pThing->pGrantCache = GnttabAllocCache(MY_FIXED_RING_SIZE);
    if (pThing->pGrantCache == NULL) {
        /* Handle errors here */
        return STATUS_UNSUCCESSFUL;
    }

    /* ... */
    Pfn = GetMyBufferPhysicalPfn(pThing);

    /* This returns a GRANT_REF. This will not fail if you are using
     * the cache versions since the cache was preallocated.
     */
    pThing->Gref = GnttabGrantForeignAccessCache(pThing->BackendDomid,
                                                 Pfn,
                                                 GRANT_MODE_RW,
                                                 pThing->pGrantCache);
    /* Because the grant cache is pre-populated with enough grefs
     * that we never run out.
     */
    ASSERT(!is_null_GRANT_REF(pThing->Gref));

    /* Write grant ref values to xenstore to allow the backend to
     * find them as in GrantAndEventChannelInATransaction() above.
     */

    /* ... */

    return STATUS_SUCCESS;
}

static VOID
UninitializeMyGrants(struct THING *pThing)
{
    NTSTATUS Status;

    Status = GnttabEndForeignAccessCache(pThing->Gref,
                                         pThing->pGrantCache);
    ASSERT(NT_SUCCESS(Status));
    pThing->Gref = null_GRANT_REF();

    /* After all foreign access is closed out, the cache can
     * be cleaned up.
     */
    GnttabFreeCache(pThing->pGrantCache);
}
