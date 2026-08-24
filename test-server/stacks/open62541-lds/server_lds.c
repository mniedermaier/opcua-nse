/* An open62541 Local Discovery Server with the multicast extension.
 *
 * FindServersOnNetwork is the one discovery service the matrix could not
 * exercise: no ordinary server implements it, only an LDS-ME does. This one
 * announces itself over mDNS and answers the service, so opcua-discover's
 * handling of it is covered by more than its rejection path.
 */

#include <open62541.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    UA_UInt16 port = 4840;
    const char *env_port = getenv("OPCUA_PORT");
    if (env_port) {
        port = (UA_UInt16)atoi(env_port);
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, port, NULL);

    /* Announce ourselves as a discovery server rather than a plain server. */
    config->applicationDescription.applicationType =
        UA_APPLICATIONTYPE_DISCOVERYSERVER;
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri =
        UA_STRING_ALLOC("urn:opcua-nse:test:lds");
    UA_LocalizedText_clear(&config->applicationDescription.applicationName);
    config->applicationDescription.applicationName =
        UA_LOCALIZEDTEXT_ALLOC("en-US", "OPC UA Test Discovery Server");

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    config->mdnsEnabled = true;
    UA_String_clear(&config->mdnsConfig.mdnsServerName);
    config->mdnsConfig.mdnsServerName = UA_STRING_ALLOC("opcua-nse-lds");

    /* The capabilities an LDS advertises on the network. */
    config->mdnsConfig.serverCapabilitiesSize = 1;
    config->mdnsConfig.serverCapabilities =
        (UA_String *)UA_Array_new(1, &UA_TYPES[UA_TYPES_STRING]);
    config->mdnsConfig.serverCapabilities[0] = UA_STRING_ALLOC("LDS");
    printf("multicast discovery enabled\n");
#else
    printf("built without multicast discovery; FindServersOnNetwork will be "
           "answered from the local registry only\n");
#endif

    printf("LDS listening on port %u\n", (unsigned)port);
    fflush(stdout);

    UA_StatusCode status = UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server);
    return status == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
