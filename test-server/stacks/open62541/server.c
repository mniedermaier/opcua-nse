/* open62541 server for the opcua-nse test matrix.
 *
 * A third protocol implementation, in C, with an address space built by hand.
 * It differs from the Python and JavaScript servers in the details the NSE
 * decoder is sensitive to: string NodeIds instead of numeric ones, its own
 * choice of encodings, and its own chunking behaviour.
 */

#include <open62541.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static volatile UA_Boolean running = true;

static void stop_handler(int sig) {
    (void)sig;
    running = false;
}

/* Adds a Double variable with the given access level to the parent object. */
static void add_double(UA_Server *server, UA_NodeId parent, const char *name,
                       UA_Double value, UA_Byte access_level) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_Variant_setScalar(&attr.value, &value, &UA_TYPES[UA_TYPES_DOUBLE]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)name);
    attr.dataType = UA_TYPES[UA_TYPES_DOUBLE].typeId;
    attr.accessLevel = access_level;
    attr.userAccessLevel = access_level;

    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, (char *)name), parent,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                              UA_QUALIFIEDNAME(1, (char *)name),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              attr, NULL, NULL);
}

static void add_string_variable(UA_Server *server, UA_NodeId parent,
                                const char *name, const char *value) {
    UA_VariableAttributes attr = UA_VariableAttributes_default;
    UA_String text = UA_STRING((char *)value);
    UA_Variant_setScalar(&attr.value, &text, &UA_TYPES[UA_TYPES_STRING]);
    attr.displayName = UA_LOCALIZEDTEXT("en-US", (char *)name);
    attr.dataType = UA_TYPES[UA_TYPES_STRING].typeId;
    attr.accessLevel = UA_ACCESSLEVELMASK_READ;
    attr.userAccessLevel = UA_ACCESSLEVELMASK_READ;

    UA_Server_addVariableNode(server, UA_NODEID_STRING(1, (char *)name), parent,
                              UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                              UA_QUALIFIEDNAME(1, (char *)name),
                              UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE),
                              attr, NULL, NULL);
}

int main(void) {
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);

    UA_UInt16 port = 48020;
    const char *env_port = getenv("OPCUA_PORT");
    if (env_port) {
        port = (UA_UInt16)atoi(env_port);
    }

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setMinimal(config, port, NULL);

    /* Identify this server the way the other test servers do. */
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri =
        UA_STRING_ALLOC("urn:opcua-nse:test:open62541");
    UA_LocalizedText_clear(&config->applicationDescription.applicationName);
    config->applicationDescription.applicationName =
        UA_LOCALIZEDTEXT_ALLOC("en-US", "OPC UA Test Server (open62541)");

    UA_String_clear(&config->buildInfo.manufacturerName);
    config->buildInfo.manufacturerName = UA_STRING_ALLOC("open62541");
    UA_String_clear(&config->buildInfo.productName);
    config->buildInfo.productName = UA_STRING_ALLOC("opcua-nse test server (open62541)");
    UA_String_clear(&config->buildInfo.buildNumber);
    config->buildInfo.buildNumber = UA_STRING_ALLOC("7");

    /* A folder with three writable variables and one read-only, matching the
     * other servers so the same assertions hold. */
    UA_ObjectAttributes folder_attr = UA_ObjectAttributes_default;
    folder_attr.displayName = UA_LOCALIZEDTEXT("en-US", "Plant");
    UA_NodeId plant = UA_NODEID_STRING(1, "Plant");
    UA_Server_addObjectNode(server, plant,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                            UA_QUALIFIEDNAME(1, "Plant"),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_FOLDERTYPE),
                            folder_attr, NULL, NULL);

    UA_Byte writable = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    add_double(server, plant, "Temperature", 20.5, writable);
    add_double(server, plant, "Pressure", 101.3, writable);
    add_double(server, plant, "Setpoint", 21.0, writable);
    add_string_variable(server, plant, "SerialNumber", "SN-000042");

    printf("open62541 server listening on port %u\n", (unsigned)port);
    fflush(stdout);

    UA_StatusCode status = UA_Server_runUntilInterrupt(server);
    UA_Server_delete(server);
    return status == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
