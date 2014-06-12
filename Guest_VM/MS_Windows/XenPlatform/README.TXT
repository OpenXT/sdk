== XenPlatform ==

The XenPlatform package contains a library that can be used to access basic
Xen platform functionality from kernel mode in Windows. It is actually
comprised of source code that would be built into a project to allow a
custom driver to link with the Xen platform API. The package contains:

xenplatform_api.h: definitions and comments for the Xen platform API functions.
xenplatform_link.h: header defining the interface for accessing the platform API.
xenplatform_link.c: implementation of the interface for accessing the platform API.
xenplatform_samples.c: some sample code showing how the bits of the platform API is used.

See the header files for more in depth information on the platform API functions
and the function used to link to the platform API.

To get just one or two function pointers, something like this can be done. Call
XenPlatformLink() to link to the platform drivers and get the base pointer.
Pass the base pointer to XenPlatformResolveEntryPoint() for as many of the
functions defined in XenPlatformFunctions as are wanted. When the platform API
is no longer needed call XenPlatformUnlink() (actually this can be called
at any point after getting the required function pointers).

Alternately, as a convenience, all the functions in the platform API can be
fetched in a single call to XenPlatformRegisterApiFunctions(). This will 
return a struct XenPlatformApiCalls with the function pointers set. Note
that if some functions are not found they may be NULL in the structure so
this should be tested for.


